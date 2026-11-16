"""Use case: Collect threat intelligence from all configured sources.

Orchestrates parallel source fetching via ThreadPoolExecutor, whitelist
filtering, dedup analysis, and health tracking.
"""

from __future__ import annotations

import logging
import time
from dataclasses import replace
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, FrozenSet, List, Set

from threat_intel.domain.entities import (
    CollectionResult,
    IPAddress,
    SourceHealthRecord,
    SourceResult,
    WhitelistHit,
)
from threat_intel.domain.ports import (
    HealthRepository,
    ThreatSource,
    WhitelistRepository,
)
from threat_intel.domain.services import (
    IndicatorBuilder,
    OverlapAnalyzer,
    WhitelistFilter,
)
from threat_intel.infrastructure.cache.source_cache import SourceCacheRepository

logger = logging.getLogger(__name__)

# Sources that manage their own cache (skip general cache for these)
_SELF_CACHED_SOURCES = frozenset({"AbuseIPDB", "AlienVault OTX"})


class CollectThreatIntelUseCase:
    """Collects IPs from all sources, applies whitelist, computes overlap."""

    def __init__(
        self,
        sources: List[ThreatSource],
        whitelist_repo: WhitelistRepository,
        health_repo: HealthRepository,
        source_cache: SourceCacheRepository,
        max_workers: int = 10,
    ):
        self._sources = sources
        self._whitelist_repo = whitelist_repo
        self._health_repo = health_repo
        self._source_cache = source_cache
        self._max_workers = max_workers

    def execute(self) -> CollectionResult:
        start = datetime.now(timezone.utc)

        whitelist_entries = self._whitelist_repo.load()
        wl_filter = WhitelistFilter(whitelist_entries)
        if wl_filter.entry_count > 0:
            logger.info(f"Whitelist loaded: {wl_filter.entry_count} entries")

        logger.info(f"Scanning {len(self._sources)} sources in parallel...")

        # Parallel fetch — each source runs in its own thread
        fetch_start = time.perf_counter()
        source_results = self._fetch_all_parallel()
        logger.info("Timing: fetching %.2fs", time.perf_counter() - fetch_start)
        processing_start = time.perf_counter()

        # Update health records
        self._update_health(source_results, start)

        # Aggregate IPs with source attribution + whitelist tracking
        ip_to_sources: Dict[str, Set[str]] = defaultdict(set)
        ip_objects: Dict[str, IPAddress] = {}
        wl_ip_to_sources: Dict[str, Set[str]] = defaultdict(set)
        wl_ip_objects: Dict[str, IPAddress] = {}

        for result in source_results:
            if not result.is_success and not result.from_cache and not result.partial:
                continue
            for ip in result.ips:
                if wl_filter.is_whitelisted(ip):
                    wl_ip_to_sources[ip.raw].add(result.source_name)
                    wl_ip_objects[ip.raw] = ip
                else:
                    ip_to_sources[ip.raw].add(result.source_name)
                    ip_objects[ip.raw] = ip

        # Build whitelist hits
        whitelist_hits = [
            WhitelistHit(
                ip=wl_ip_objects[ip_raw],
                sources=frozenset(srcs),
            )
            for ip_raw, srcs in wl_ip_to_sources.items()
        ]

        # Freeze source sets
        frozen_ip_sources = {
            ip: frozenset(srcs) for ip, srcs in ip_to_sources.items()
        }

        # Build indicators
        indicators = IndicatorBuilder.build(
            frozen_ip_sources, ip_objects, start
        )

        # Compute overlap metrics
        source_names = [s.name for s in self._sources]
        overlap = OverlapAnalyzer.analyze(frozen_ip_sources, source_names)

        logger.info("Timing: processing %.2fs", time.perf_counter() - processing_start)
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()

        return CollectionResult(
            timestamp=start,
            elapsed_seconds=round(elapsed, 2),
            source_results=source_results,
            indicators=indicators,
            whitelist_hits=whitelist_hits,
            overlap=overlap,
        )

    def _fetch_all_parallel(self) -> List[SourceResult]:
        """Launch all source fetches in parallel via ThreadPoolExecutor."""
        results: List[SourceResult] = []

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            futures = {
                pool.submit(self._safe_fetch, source): source
                for source in self._sources
            }
            for future in as_completed(futures):
                results.append(future.result())

        return sorted(results, key=lambda r: r.source_name)

    def _safe_fetch(self, source: ThreatSource) -> SourceResult:
        started = time.perf_counter()
        result = self._fetch_source(source)
        elapsed = round(time.perf_counter() - started, 2)
        if result.from_cache:
            log = logger.warning if result.error else logger.info
            log("[%s] Cache reason: %s", source.name,
                result.cache_reason or result.error or "Reason unavailable")
        logger.info("Timing: [%s] %.2fs%s", source.name, elapsed,
                    " (cache fallback)" if result.from_cache and result.error else "")
        return replace(result, elapsed_seconds=elapsed)

    def _fetch_source(self, source: ThreatSource) -> SourceResult:
        """Run a single source fetch, catching all exceptions.

        On success: caches IPs for future fallback.
        On failure: serves last cached IPs (if any) and preserves the error.
        """
        skip_cache = source.name in _SELF_CACHED_SOURCES

        try:
            fetch_result = getattr(source, "fetch_result", None)
            if fetch_result is not None:
                result = fetch_result()
                logger.info("[%s] %s IPs%s", source.name, result.ip_count,
                            " [CACHED]" if result.from_cache else "")
                if not skip_cache and result.is_success and not result.from_cache and result.ips:
                    self._source_cache.save(source.name, result.ips)
                return result
            ips = source.fetch()
            logger.info(f"[{source.name}] {len(ips)} IPs")

            if not skip_cache and ips:
                self._source_cache.save(source.name, ips)

            return SourceResult(
                source_name=source.name,
                ips=frozenset(ips),
            )
        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            logger.error(f"[{source.name}] {error_msg}")

            cached_ips: Set[IPAddress] = set()
            observed_at = None
            if not skip_cache:
                cached = self._source_cache.load_result(source.name)
                cached_ips = set(cached.ips)
                observed_at = cached.observed_at
                if cached_ips:
                    logger.info(
                        f"[{source.name}] Serving {len(cached_ips)} IPs from cache"
                    )

            return SourceResult(
                source_name=source.name,
                ips=frozenset(cached_ips),
                error=error_msg,
                from_cache=bool(cached_ips),
                observed_at=observed_at,
                cache_reason=f"Fetch failed: {error_msg}" if cached_ips else None,
            )

    def _update_health(self, results: List[SourceResult], now: datetime):
        active_names = {result.source_name for result in results}
        health = self._health_repo.load_all()

        for result in results:
            name = result.source_name
            record = health.get(name, SourceHealthRecord(source_name=name))

            if result.error:
                record = record.with_failure(result.error, now)
            elif result.from_cache or result.skipped:
                # Cache use is not a new successful observation and must not reset failures.
                if record.last_success is None and result.observed_at is not None:
                    record = replace(record, last_success=result.observed_at,
                                     last_ip_count=result.ip_count)
                if not result.skipped:
                    record = record.with_no_data()
            elif result.ip_count == 0:
                record = record.with_no_data()
            else:
                record = record.with_success(result.ip_count, now)

            health[name] = record

        # Drop records for sources that are no longer registered. Otherwise a
        # removed feed lingers as permanently "stale", which keeps the health
        # report's alert condition true forever and prevents resolved health
        # issues from ever being auto-closed.
        health = {
            name: record
            for name, record in health.items()
            if name in active_names
        }

        self._health_repo.save_all(health)

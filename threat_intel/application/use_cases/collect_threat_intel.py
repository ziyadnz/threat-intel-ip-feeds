"""Use case: Collect threat intelligence from all configured sources.

Orchestrates concurrent source fetching via asyncio.gather, whitelist filtering,
dedup analysis, and health tracking. Depends only on domain ports and services.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
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
        max_concurrency: int = 5,
    ):
        self._sources = sources
        self._whitelist_repo = whitelist_repo
        self._health_repo = health_repo
        self._source_cache = source_cache
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def execute(self) -> CollectionResult:
        start = datetime.now(timezone.utc)

        whitelist_entries = self._whitelist_repo.load()
        wl_filter = WhitelistFilter(whitelist_entries)
        if wl_filter.entry_count > 0:
            logger.info(f"Whitelist loaded: {wl_filter.entry_count} entries")

        logger.info(f"Scanning {len(self._sources)} sources concurrently...")

        # Concurrent fetch — each source is isolated via its own coroutine
        source_results = await self._fetch_all_concurrent()

        # Update health records
        self._update_health(source_results, start)

        # Aggregate IPs with source attribution + whitelist tracking
        ip_to_sources: Dict[str, Set[str]] = defaultdict(set)
        ip_objects: Dict[str, IPAddress] = {}
        wl_ip_to_sources: Dict[str, Set[str]] = defaultdict(set)
        wl_ip_objects: Dict[str, IPAddress] = {}

        for result in source_results:
            if not result.is_success:
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

        elapsed = (datetime.now(timezone.utc) - start).total_seconds()

        return CollectionResult(
            timestamp=start,
            elapsed_seconds=round(elapsed, 2),
            source_results=source_results,
            indicators=indicators,
            whitelist_hits=whitelist_hits,
            overlap=overlap,
        )

    async def _fetch_all_concurrent(self) -> List[SourceResult]:
        """Launch all source fetches with bounded concurrency via semaphore.

        At most max_concurrency sources run simultaneously.
        This prevents API throttling from services that detect
        concurrent connection bursts from the same IP.
        """
        tasks = [
            self._safe_fetch_with_limit(source)
            for source in self._sources
        ]
        return list(await asyncio.gather(*tasks))

    async def _safe_fetch_with_limit(self, source: ThreatSource) -> SourceResult:
        """Acquire semaphore before fetching — limits concurrent requests."""
        async with self._semaphore:
            return await self._safe_fetch(source)

    async def _safe_fetch(self, source: ThreatSource) -> SourceResult:
        """Run a single source fetch, catching all exceptions.

        On success: caches IPs for future fallback.
        On failure: serves last cached IPs (if any) and preserves the error.
        """
        skip_cache = source.name in _SELF_CACHED_SOURCES

        try:
            ips = await source.fetch()
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
            if not skip_cache:
                cached_ips = self._source_cache.load(source.name)
                if cached_ips:
                    logger.info(
                        f"[{source.name}] Serving {len(cached_ips)} IPs from cache"
                    )

            return SourceResult(
                source_name=source.name,
                ips=frozenset(cached_ips),
                error=error_msg,
                from_cache=bool(cached_ips),
            )

    def _update_health(self, results: List[SourceResult], now: datetime):
        health = self._health_repo.load_all()

        for result in results:
            name = result.source_name
            record = health.get(name, SourceHealthRecord(source_name=name))

            if result.error:
                record = record.with_failure(result.error, now)
            elif result.ip_count == 0:
                record = record.with_no_data()
            else:
                record = record.with_success(result.ip_count, now)

            health[name] = record

        self._health_repo.save_all(health)

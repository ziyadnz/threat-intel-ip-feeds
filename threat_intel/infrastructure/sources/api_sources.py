"""Rate-limited API sources with explicit cache freshness and failure outcomes."""

from __future__ import annotations

import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Set

from threat_intel.domain.entities import IPAddress, SourceResult
from threat_intel.domain.ports import HttpClient, ThreatSource
from threat_intel.domain.services import IPValidator
from threat_intel.infrastructure.sources.urls import ABUSEIPDB_BLACKLIST, ALIENVAULT_OTX_PULSES

logger = logging.getLogger(__name__)


class _CachedAPISource(ThreatSource):
    """Persist successful fetches atomically; never present fallback as fresh data."""

    def fetch(self) -> Set[IPAddress]:
        return set(self.fetch_result().ips)

    def _cached_result(self, error=None, skipped=False):
        ips, observed_at = set(), None
        try:
            with open(self._cache_path, encoding="utf-8") as f:
                data = json.load(f)
            for raw in data.get("ips", []):
                ip = IPAddress.parse(raw)
                if ip:
                    ips.add(ip)
            observed_at = datetime.fromisoformat(data["timestamp"])
            if observed_at.tzinfo is None or observed_at > datetime.now(timezone.utc):
                observed_at = None
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            pass
        return SourceResult(self.name, frozenset(ips), error=error,
                            from_cache=bool(ips), skipped=skipped,
                            observed_at=observed_at)

    def _save_cache(self, ips, now):
        try:
            os.makedirs(os.path.dirname(self._cache_path), exist_ok=True)
            tmp = self._cache_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"timestamp": now.isoformat(),
                           "ips": sorted(ip.raw for ip in ips)}, f)
            os.replace(tmp, self._cache_path)
        except OSError as e:
            logger.warning("[%s] Cache write failed: %s", self.name, e)
            try:
                os.unlink(self._cache_path + ".tmp")
            except OSError:
                pass


class AbuseIPDBSource(_CachedAPISource):
    """Refresh at most once every four hours after a successful fetch."""

    def __init__(self, http: HttpClient, api_key: str, cache_dir: str,
                 refresh_hours: float = 4, confidence_minimum: int = 90):
        self._http = http
        self._api_key = api_key
        self._cache_path = os.path.join(cache_dir, "abuseipdb_cache.json")
        self._refresh_interval = timedelta(hours=refresh_hours)
        self._confidence_min = confidence_minimum

    @property
    def name(self):
        return "AbuseIPDB"

    @property
    def category(self):
        return "crowd-sourced"

    def fetch_result(self):
        if not self._api_key:
            return SourceResult(self.name, frozenset(), skipped=True)
        now = datetime.now(timezone.utc)
        cached = self._cached_result()
        if cached.observed_at and now - cached.observed_at < self._refresh_interval:
            return cached
        headers = {"Key": self._api_key, "Accept": "application/json",
                   "User-Agent": "IP-Blacklist-Aggregator/6.0"}
        url = f"{ABUSEIPDB_BLACKLIST}?confidenceMinimum={self._confidence_min}&limit=10000"
        try:
            data = self._http.get_json(url, headers=headers)
            entries = data["data"]
            if not isinstance(entries, list):
                raise ValueError("Invalid AbuseIPDB data payload")
            ips = {ip for entry in entries
                   if (ip := IPValidator.parse_and_validate(entry.get("ipAddress", "")))}
            if not ips:
                raise ValueError("AbuseIPDB returned no valid IPs; preserving cache")
        except Exception as e:
            return self._cached_result(error=f"{type(e).__name__}: {e}")
        self._save_cache(ips, now)
        return SourceResult(self.name, frozenset(ips), observed_at=now)


class AlienVaultOTXSource(_CachedAPISource):
    """Fetch bounded page batches, honor pagination, and retain fallback data.

    Existing concurrency (3), HTTP retries/timeouts, and the two-second outer
    retry delay are preserved. Permanent HTTP errors are not retried again.
    """

    def __init__(self, http: HttpClient, api_key: str, cache_dir: str,
                 max_pages: int = 20, page_concurrency: int = 3):
        self._http = http
        self._api_key = api_key
        self._cache_path = os.path.join(cache_dir, "otx_cache.json")
        self._max_pages = max_pages
        self._page_concurrency = page_concurrency

    @property
    def name(self):
        return "AlienVault OTX"

    @property
    def category(self):
        return "threat-intel"

    def fetch_result(self):
        if not self._api_key:
            return SourceResult(self.name, frozenset(), skipped=True)
        headers = {"X-OTX-API-KEY": self._api_key,
                   "User-Agent": "IP-Blacklist-Aggregator/6.0"}
        result, failures = set(), {}
        end_page = self._max_pages
        with ThreadPoolExecutor(max_workers=self._page_concurrency) as pool:
            for first in range(1, self._max_pages + 1, self._page_concurrency):
                if first > end_page:
                    break
                pages = range(first, min(first + self._page_concurrency, end_page + 1))
                fetched = list(pool.map(lambda p: self._fetch_page(p, headers), pages))
                for page, (ips, more, error) in zip(pages, fetched):
                    if error is None and not more:
                        end_page = min(end_page, page)
                for page, (ips, more, error) in zip(pages, fetched):
                    if page > end_page:
                        continue
                    if error:
                        failures[page] = error
                    else:
                        result.update(ips)
            retryable = [p for p, e in failures.items()
                         if getattr(e, "status", 0) not in range(400, 500)
                         or getattr(e, "status", 0) == 429]
            if retryable:
                time.sleep(max(2, *(getattr(failures[p], "retry_after", 0)
                                    for p in retryable)))
                fetched = pool.map(lambda p: self._fetch_page(p, headers), retryable)
                for page, (ips, more, error) in zip(retryable, fetched):
                    if error is None:
                        if not more:
                            end_page = min(end_page, page)
                        result.update(ips)
                        del failures[page]
                    else:
                        failures[page] = error
        # A later successful end-of-feed response makes higher failed pages irrelevant.
        failures = {p: e for p, e in failures.items() if p <= end_page}
        now = datetime.now(timezone.utc)
        if failures:
            cached = self._cached_result(error="OTX pages failed: " + ", ".join(
                f"{p} ({e})" for p, e in sorted(failures.items())))
            # Keep newly obtained partial data and the previous complete snapshot.
            # Do not overwrite that snapshot or claim a fresh complete fetch.
            return SourceResult(self.name, frozenset(result | set(cached.ips)),
                                error=cached.error, from_cache=bool(cached.ips),
                                partial=bool(result),
                                observed_at=cached.observed_at)
        if not result:
            return self._cached_result(error="OTX returned no valid IPs; preserving cache")
        self._save_cache(result, now)
        return SourceResult(self.name, frozenset(result), observed_at=now)

    def _fetch_page(self, page, headers):
        url = f"{ALIENVAULT_OTX_PULSES}?limit=50&page={page}"
        try:
            data = self._http.get_json(url, headers=headers, timeout=90)
            pulses = data["results"]
            if not isinstance(pulses, list):
                raise ValueError("Invalid OTX results payload")
            ips = set()
            for pulse in pulses:
                for indicator in pulse.get("indicators", []):
                    if indicator.get("type") in ("IPv4", "IPv6"):
                        ip = IPValidator.parse_and_validate(indicator.get("indicator", ""))
                        if ip:
                            ips.add(ip)
            # Missing pagination metadata is treated conservatively, up to max_pages.
            more = bool(pulses) and bool(data.get("next", True))
            return ips, more, None
        except Exception as e:
            logger.warning("[%s] Page %s failed: %s", self.name, page, e)
            return set(), True, e

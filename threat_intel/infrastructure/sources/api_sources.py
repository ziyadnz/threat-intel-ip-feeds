"""API-authenticated threat source adapters (AbuseIPDB, AlienVault OTX).

These sources require API keys and have rate limits.
Cache management is handled here as infrastructure concern.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional, Set

from threat_intel.domain.entities import IPAddress
from threat_intel.domain.ports import HttpClient, ThreatSource
from threat_intel.domain.services import IPValidator

logger = logging.getLogger(__name__)


class AbuseIPDBSource(ThreatSource):
    """AbuseIPDB — crowd-sourced abuse reports with rate-limit-aware caching."""

    def __init__(
        self,
        http: HttpClient,
        api_key: str,
        cache_dir: str,
        allowed_hours: frozenset = frozenset({0, 5, 10, 15, 20}),
        confidence_minimum: int = 90,
    ):
        self._http = http
        self._api_key = api_key
        self._cache_path = os.path.join(cache_dir, "abuseipdb_cache.json")
        self._allowed_hours = allowed_hours
        self._confidence_min = confidence_minimum

    @property
    def name(self) -> str:
        return "AbuseIPDB"

    @property
    def category(self) -> str:
        return "crowd-sourced"

    async def fetch(self) -> Set[IPAddress]:
        if not self._api_key:
            logger.warning(f"[{self.name}] No API key, skipping.")
            return set()

        current_hour = datetime.now(timezone.utc).hour
        if current_hour not in self._allowed_hours:
            return self._load_cache()

        headers = {"Key": self._api_key, "Accept": "application/json"}
        url = (
            f"https://api.abuseipdb.com/api/v2/blacklist"
            f"?confidenceMinimum={self._confidence_min}&limit=10000"
        )
        data = await self._http.get_json(url, headers=headers)

        result = set()
        for entry in data.get("data", []):
            ip = IPValidator.parse_and_validate(entry.get("ipAddress", ""))
            if ip:
                result.add(ip)

        if result:
            self._save_cache(result)
        else:
            result = self._load_cache()

        return result

    def _save_cache(self, ips: Set[IPAddress]):
        try:
            data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ips": sorted(ip.raw for ip in ips),
            }
            with open(self._cache_path, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except OSError as e:
            logger.warning(f"[{self.name}] Cache write failed: {e}")

    def _load_cache(self) -> Set[IPAddress]:
        try:
            with open(self._cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            result = set()
            for raw in data.get("ips", []):
                ip = IPAddress.parse(raw)
                if ip:
                    result.add(ip)
            logger.info(f"[{self.name}] Loaded {len(result)} from cache")
            return result
        except (FileNotFoundError, json.JSONDecodeError):
            return set()


class AlienVaultOTXSource(ThreatSource):
    """AlienVault OTX — community threat intel pulses with pagination."""

    def __init__(
        self,
        http: HttpClient,
        api_key: str,
        max_pages: int = 20,
    ):
        self._http = http
        self._api_key = api_key
        self._max_pages = max_pages

    @property
    def name(self) -> str:
        return "AlienVault OTX"

    @property
    def category(self) -> str:
        return "threat-intel"

    async def fetch(self) -> Set[IPAddress]:
        if not self._api_key:
            logger.warning(f"[{self.name}] No API key, skipping.")
            return set()

        headers = {"X-OTX-API-KEY": self._api_key}
        result = set()
        page = 1

        while page <= self._max_pages:
            url = (
                f"https://otx.alienvault.com/api/v1/pulses/subscribed"
                f"?limit=50&page={page}"
            )
            data = await self._http.get_json(url, headers=headers)
            pulses = data.get("results", [])
            if not pulses:
                break

            for pulse in pulses:
                for indicator in pulse.get("indicators", []):
                    if indicator.get("type") in ("IPv4", "IPv6"):
                        ip = IPValidator.parse_and_validate(
                            indicator.get("indicator", "")
                        )
                        if ip:
                            result.add(ip)

            if not data.get("next"):
                break
            page += 1

        return result

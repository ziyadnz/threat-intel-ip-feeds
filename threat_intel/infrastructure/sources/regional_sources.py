"""Regional threat source adapters (Turkey: USOM, RTBH)."""

from __future__ import annotations

import asyncio
from typing import Set

from threat_intel.domain.entities import IPAddress
from threat_intel.domain.ports import HttpClient, ThreatSource
from threat_intel.domain.services import IPValidator
from threat_intel.infrastructure.sources.base import TextListSource
from threat_intel.infrastructure.sources.urls import RTBH, USOM_API


class UsomSource(ThreatSource):
    """USOM (Turkey) — government-published malicious IPs via paginated API."""

    def __init__(self, http: HttpClient, max_ips: int = 10000,
                 rate_limit_delay: float = 2.0):
        self._http = http
        self._max_ips = max_ips
        self._rate_delay = rate_limit_delay

    @property
    def name(self) -> str:
        return "USOM (Turkiye)"

    @property
    def category(self) -> str:
        return "government-feed"

    async def fetch(self) -> Set[IPAddress]:
        result = set()
        page = 1

        while len(result) < self._max_ips:
            url = f"{USOM_API}?type=ip&page={page}"
            data = await self._http.get_json(url, headers={"accept": "application/json"})

            models = data.get("models", [])
            if not models:
                break

            for entry in models:
                raw = entry.get("url", "").strip()
                ip = IPValidator.parse_and_validate(raw)
                if ip:
                    result.add(ip)
                    if len(result) >= self._max_ips:
                        break

            total_count = data.get("totalCount", 0)
            page_size = data.get("pageSize", 100)
            if page * page_size >= total_count:
                break
            page += 1
            await asyncio.sleep(self._rate_delay)

        return result


class RtbhSource(TextListSource):
    """RTBH (Turkey) — national-level blocklist."""

    def __init__(self, http: HttpClient):
        super().__init__(http, "RTBH (Turkiye)", RTBH, "government-feed")

"""Global threat source adapters (no registration required).

Each class implements ThreatSource and encapsulates one feed's parsing logic.
HTTP is injected via the async HttpClient port — never imported directly.
"""

from __future__ import annotations

from typing import Set

from threat_intel.domain.entities import IPAddress
from threat_intel.domain.ports import HttpClient
from threat_intel.domain.services import IPValidator
from threat_intel.infrastructure.sources.base import TextListSource


class SpamhausDropSource(TextListSource):
    """Spamhaus DROP — hijacked network CIDRs."""

    def __init__(self, http: HttpClient):
        super().__init__(http, "Spamhaus DROP",
                         "https://www.spamhaus.org/drop/drop.txt",
                         "infrastructure")

    def _parse(self, text: str) -> Set[IPAddress]:
        result = set()
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith(";"):
                cidr = line.split(";")[0].strip()
                if "/" in cidr:
                    ip = IPAddress.parse(cidr)
                    if ip:
                        result.add(ip)
        return result


class SpamhausDropV6Source(TextListSource):
    """Spamhaus DROPv6 — hijacked IPv6 CIDRs."""

    def __init__(self, http: HttpClient):
        super().__init__(http, "Spamhaus DROPv6",
                         "https://www.spamhaus.org/drop/dropv6.txt",
                         "infrastructure")

    def _parse(self, text: str) -> Set[IPAddress]:
        result = set()
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith(";"):
                cidr = line.split(";")[0].strip()
                if "/" in cidr:
                    ip = IPAddress.parse(cidr)
                    if ip:
                        result.add(ip)
        return result


class FeodoTrackerSource(TextListSource):
    """Feodo Tracker (abuse.ch) — botnet C2 server IPs."""

    def __init__(self, http: HttpClient):
        super().__init__(http, "Feodo Tracker",
                         "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
                         "botnet-c2")


class DShieldSource:
    """DShield/SANS ISC — JSON intel feed."""

    def __init__(self, http: HttpClient):
        self._http = http

    @property
    def name(self) -> str:
        return "DShield"

    @property
    def category(self) -> str:
        return "scanner"

    async def fetch(self) -> Set[IPAddress]:
        headers = {"User-Agent": "IP-Blacklist-Aggregator/4.0"}
        data = await self._http.get_json(
            "https://isc.sans.edu/api/intelfeed?json",
            headers=headers,
        )
        result = set()
        if isinstance(data, list):
            for entry in data:
                raw = entry.get("ip", "")
                ip = IPValidator.parse_and_validate(raw)
                if ip:
                    result.add(ip)
        return result


class BlocklistDeSource(TextListSource):
    """Blocklist.de — attack IPs by category."""

    def __init__(self, http: HttpClient, service: str = "all"):
        super().__init__(
            http,
            f"Blocklist.de ({service})",
            f"https://lists.blocklist.de/lists/{service}.txt",
            "attacker",
        )


class CinsArmySource(TextListSource):
    def __init__(self, http: HttpClient):
        super().__init__(http, "CINS Army",
                         "https://cinsscore.com/list/ci-badguys.txt",
                         "scanner")


class EmergingThreatsSource(TextListSource):
    def __init__(self, http: HttpClient):
        super().__init__(http, "Emerging Threats",
                         "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                         "compromised")


class BinaryDefenseSource(TextListSource):
    """BinaryDefense Artillery ban list — custom parsing for comment lines."""

    def __init__(self, http: HttpClient):
        super().__init__(http, "BinaryDefense",
                         "https://www.binarydefense.com/banlist.txt",
                         "attacker")

    def _parse(self, text: str) -> Set[IPAddress]:
        result = set()
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ip = IPValidator.parse_and_validate(line)
                if ip:
                    result.add(ip)
        return result


class GreenSnowSource(TextListSource):
    def __init__(self, http: HttpClient):
        super().__init__(http, "GreenSnow",
                         "https://blocklist.greensnow.co/greensnow.txt",
                         "attacker")


class TorExitSource(TextListSource):
    def __init__(self, http: HttpClient):
        super().__init__(http, "Tor Exit Nodes",
                         "https://check.torproject.org/torbulkexitlist",
                         "anonymizer")


class StamparmIpsumSource:
    """Stamparm IPsum — multi-source aggregation with score threshold."""

    def __init__(self, http: HttpClient, min_score: int = 2):
        self._http = http
        self._min_score = min_score

    @property
    def name(self) -> str:
        return "Stamparm IPsum"

    @property
    def category(self) -> str:
        return "multi-source"

    async def fetch(self) -> Set[IPAddress]:
        text = await self._http.get(
            "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
            timeout=120,
        )
        result = set()
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split("\t")
                if len(parts) >= 2:
                    try:
                        score = int(parts[1])
                    except ValueError:
                        continue
                    if score >= self._min_score:
                        ip = IPValidator.parse_and_validate(parts[0])
                        if ip:
                            result.add(ip)
        return result

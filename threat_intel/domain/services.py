"""Domain services — pure business logic, no I/O.

These operate on domain entities and value objects only.
They encode the rules of the threat intelligence domain.
"""

from __future__ import annotations

from collections import defaultdict
import ipaddress
from itertools import combinations
from typing import Dict, FrozenSet, List, Set

from threat_intel.domain.entities import (
    ConfidenceScore,
    IPAddress,
    OverlapMetrics,
    ThreatCategory,
    ThreatIndicator,
    WhitelistEntry,
)


# ---------------------------------------------------------------------------
# Source -> Category mapping (domain knowledge)
# ---------------------------------------------------------------------------

SOURCE_CATEGORY_MAP: Dict[str, ThreatCategory] = {
    "Spamhaus DROP": ThreatCategory.INFRASTRUCTURE,
    "Spamhaus DROPv6": ThreatCategory.INFRASTRUCTURE,
    "Blocklist.de (all)": ThreatCategory.ATTACKER,
    "Blocklist.de (ssh)": ThreatCategory.BRUTE_FORCE,
    "Blocklist.de (mail)": ThreatCategory.SPAM,
    "Blocklist.de (apache)": ThreatCategory.WEB_ATTACK,
    "Blocklist.de (bots)": ThreatCategory.BOTNET,
    "Blocklist.de (bruteforcelogin)": ThreatCategory.BRUTE_FORCE,
    "Blocklist.de (strongips)": ThreatCategory.ATTACKER,
    "CINS Army": ThreatCategory.SCANNER,
    "Emerging Threats": ThreatCategory.COMPROMISED,
    "BinaryDefense": ThreatCategory.ATTACKER,
    "GreenSnow": ThreatCategory.ATTACKER,
    "Tor Exit Nodes": ThreatCategory.ANONYMIZER,
    "Stamparm IPsum": ThreatCategory.MULTI_SOURCE,
    "SGB (Turkiye)": ThreatCategory.GOVERNMENT_FEED,
    "RTBH (Turkiye)": ThreatCategory.GOVERNMENT_FEED,
    "AbuseIPDB": ThreatCategory.CROWD_SOURCED,
    "AlienVault OTX": ThreatCategory.THREAT_INTEL,
}


def resolve_category(sources: FrozenSet[str]) -> ThreatCategory:
    """Determine threat category from a set of source names."""
    for source in sorted(sources):
        cat = SOURCE_CATEGORY_MAP.get(source)
        if cat is not None:
            return cat
    return ThreatCategory.UNKNOWN


# ---------------------------------------------------------------------------
# Whitelist Filter (domain service)
# ---------------------------------------------------------------------------

class WhitelistFilter:
    """Filters IPs against a set of whitelist entries. Pure logic, no I/O."""

    def __init__(self, entries: List[WhitelistEntry]):
        self._entries = entries
        self._addresses = {e._address for e in entries if e._address is not None}
        self._networks = [e._network for e in entries if e._network is not None]

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def is_whitelisted(self, ip: IPAddress) -> bool:
        if not self._entries:
            return False
        if ip.is_cidr:
            target = ipaddress.ip_network(ip.raw)
            return (any(a.version == target.version and a in target for a in self._addresses)
                    or any(n.version == target.version and n.overlaps(target)
                           for n in self._networks))
        target = ipaddress.ip_address(ip.raw)
        return target in self._addresses or any(
            n.version == target.version and target in n for n in self._networks
        )

    def filter_set(self, ips: Set[IPAddress]) -> tuple:
        """Return (kept, filtered_count)."""
        kept = set()
        filtered = 0
        for ip in ips:
            if self.is_whitelisted(ip):
                filtered += 1
            else:
                kept.add(ip)
        return kept, filtered


# ---------------------------------------------------------------------------
# IP Validator (domain service)
# ---------------------------------------------------------------------------

class IPValidator:
    """Validates and parses raw IP strings into domain IPAddress objects."""

    @staticmethod
    def parse_and_validate(raw: str) -> IPAddress | None:
        """Parse a raw IP string; return IPAddress if valid and public, else None."""
        ip = IPAddress.parse(raw)
        if ip is None:
            return None
        if not ip.is_public:
            return None
        return ip


# ---------------------------------------------------------------------------
# Overlap Analyzer (domain service)
# ---------------------------------------------------------------------------

class OverlapAnalyzer:
    """Computes deduplication metrics across sources. Pure computation."""

    @staticmethod
    def analyze(ip_to_sources: Dict[str, FrozenSet[str]],
                source_names: List[str]) -> OverlapMetrics:
        total = len(ip_to_sources)
        if total == 0:
            return OverlapMetrics()

        source_counts = [len(srcs) for srcs in ip_to_sources.values()]
        unique_count = sum(1 for c in source_counts if c == 1)
        multi_count = total - unique_count
        max_overlap = max(source_counts)
        avg = sum(source_counts) / total

        # Count memberships and pairs once instead of rescanning all IPs per pair.
        per_source_unique = dict.fromkeys(source_names, 0)
        per_source_shared = dict.fromkeys(source_names, 0)
        pair_counts = defaultdict(int)
        rank = {name: i for i, name in enumerate(source_names)}
        for sources in ip_to_sources.values():
            active = sorted((s for s in sources if s in rank), key=rank.get)
            counts = per_source_unique if len(sources) == 1 else per_source_shared
            for src in active:
                counts[src] += 1
            for pair in combinations(active, 2):
                pair_counts[pair] += 1
        ordered = sorted(pair_counts, key=lambda p: (-pair_counts[p], rank[p[0]], rank[p[1]]))
        top_pairs = {f"{a} & {b}": pair_counts[a, b] for a, b in ordered[:10]}

        return OverlapMetrics(
            unique_single_source=unique_count,
            found_in_multiple=multi_count,
            max_source_overlap=max_overlap,
            avg_sources_per_ip=round(avg, 2),
            per_source_unique=per_source_unique,
            per_source_shared=per_source_shared,
            top_pair_overlaps=top_pairs,
        )


# ---------------------------------------------------------------------------
# Indicator Builder (domain service)
# ---------------------------------------------------------------------------

class IndicatorBuilder:
    """Builds ThreatIndicator entities from raw source results."""

    @staticmethod
    def build(ip_to_sources: Dict[str, FrozenSet[str]],
              ip_objects: Dict[str, IPAddress],
              timestamp) -> List[ThreatIndicator]:
        indicators = []
        for ip_raw, sources in ip_to_sources.items():
            ip_obj = ip_objects.get(ip_raw)
            if ip_obj is None:
                continue
            category = resolve_category(sources)
            indicator = ThreatIndicator.create(
                ip=ip_obj,
                sources=sources,
                category=category,
                timestamp=timestamp,
            )
            indicators.append(indicator)
        return indicators

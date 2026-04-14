"""Domain services — pure business logic, no I/O.

These operate on domain entities and value objects only.
They encode the rules of the threat intelligence domain.
"""

from __future__ import annotations

from collections import defaultdict
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
    "Feodo Tracker": ThreatCategory.BOTNET_C2,
    "DShield": ThreatCategory.SCANNER,
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
    "USOM (Turkiye)": ThreatCategory.GOVERNMENT_FEED,
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

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def is_whitelisted(self, ip: IPAddress) -> bool:
        return any(entry.covers(ip) for entry in self._entries)

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

        # Per-source unique vs shared
        per_source_unique = {}
        per_source_shared = {}
        for src in source_names:
            src_ips = [ip for ip, srcs in ip_to_sources.items() if src in srcs]
            uniq = sum(1 for ip in src_ips if len(ip_to_sources[ip]) == 1)
            per_source_unique[src] = uniq
            per_source_shared[src] = len(src_ips) - uniq

        # Top pair overlaps
        active_sources = [s for s in source_names
                          if per_source_unique.get(s, 0) + per_source_shared.get(s, 0) > 0]
        pair_overlap = {}
        for i, s1 in enumerate(active_sources):
            s1_ips = {ip for ip, srcs in ip_to_sources.items() if s1 in srcs}
            for s2 in active_sources[i + 1:]:
                s2_ips = {ip for ip, srcs in ip_to_sources.items() if s2 in srcs}
                shared = len(s1_ips & s2_ips)
                if shared > 0:
                    pair_overlap[f"{s1} & {s2}"] = shared

        top_pairs = dict(sorted(pair_overlap.items(), key=lambda x: -x[1])[:10])

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

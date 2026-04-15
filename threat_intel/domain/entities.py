"""Domain entities and value objects.

All classes here are pure Python — no framework imports, no I/O, no side effects.
They represent the core concepts of the threat intelligence domain.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import FrozenSet, Optional


# ---------------------------------------------------------------------------
# Value Objects (immutable, identity-less, compared by value)
# ---------------------------------------------------------------------------

class IPVersion(Enum):
    V4 = "ipv4"
    V6 = "ipv6"


class ThreatCategory(Enum):
    INFRASTRUCTURE = "infrastructure"
    BOTNET_C2 = "botnet-c2"
    SCANNER = "scanner"
    ATTACKER = "attacker"
    BRUTE_FORCE = "brute-force"
    SPAM = "spam"
    WEB_ATTACK = "web-attack"
    BOTNET = "botnet"
    COMPROMISED = "compromised"
    ANONYMIZER = "anonymizer"
    MULTI_SOURCE = "multi-source"
    GOVERNMENT_FEED = "government-feed"
    CROWD_SOURCED = "crowd-sourced"
    THREAT_INTEL = "threat-intel"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class IPAddress:
    """Validated, classified IP address or CIDR range."""

    raw: str
    version: IPVersion
    is_cidr: bool

    @staticmethod
    def parse(raw: str) -> Optional[IPAddress]:
        """Parse and validate a raw IP/CIDR string. Returns None if invalid."""
        raw = raw.strip()
        if not raw:
            return None

        is_cidr = "/" in raw
        try:
            if is_cidr:
                net = ipaddress.ip_network(raw, strict=False)
                version = IPVersion.V6 if net.version == 6 else IPVersion.V4
            else:
                addr = ipaddress.ip_address(raw)
                version = IPVersion.V6 if addr.version == 6 else IPVersion.V4
        except ValueError:
            return None

        return IPAddress(raw=raw, version=version, is_cidr=is_cidr)

    @property
    def is_public(self) -> bool:
        try:
            if self.is_cidr:
                net = ipaddress.ip_network(self.raw, strict=False)
                return not net.is_private
            addr = ipaddress.ip_address(self.raw)
            return not (
                addr.is_private or addr.is_loopback
                or addr.is_reserved or addr.is_multicast
            )
        except ValueError:
            return False


@dataclass(frozen=True)
class ConfidenceScore:
    """0–100 confidence score derived from number of reporting sources."""

    value: int

    def __post_init__(self):
        object.__setattr__(self, "value", max(0, min(100, self.value)))

    @staticmethod
    def from_source_count(count: int, weight_per_source: int = 20) -> ConfidenceScore:
        return ConfidenceScore(value=min(count * weight_per_source, 100))


@dataclass(frozen=True)
class WhitelistEntry:
    """A single whitelist entry — either an individual IP or a CIDR range."""

    _address: Optional[object] = field(repr=False, default=None)
    _network: Optional[object] = field(repr=False, default=None)
    raw: str = ""

    @staticmethod
    def parse(raw: str) -> Optional[WhitelistEntry]:
        raw = raw.strip()
        if not raw:
            return None
        try:
            if "/" in raw:
                net = ipaddress.ip_network(raw, strict=False)
                return WhitelistEntry(_network=net, raw=raw)
            else:
                addr = ipaddress.ip_address(raw)
                return WhitelistEntry(_address=addr, raw=raw)
        except ValueError:
            return None

    def covers(self, ip: IPAddress) -> bool:
        """Return True if this whitelist entry covers the given IP."""
        try:
            if ip.is_cidr:
                target_net = ipaddress.ip_network(ip.raw, strict=False)
                if self._network is not None:
                    if target_net.version != self._network.version:
                        return False
                    return target_net.subnet_of(self._network)
                return False
            else:
                target_addr = ipaddress.ip_address(ip.raw)
                if self._address is not None:
                    return target_addr == self._address
                if self._network is not None:
                    if target_addr.version != self._network.version:
                        return False
                    return target_addr in self._network
                return False
        except (ValueError, TypeError):
            return False


# ---------------------------------------------------------------------------
# Entities (identity matters)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ThreatIndicator:
    """A single malicious IP with full provenance metadata."""

    ip: IPAddress
    sources: FrozenSet[str]
    category: ThreatCategory
    confidence: ConfidenceScore
    first_seen: datetime
    last_seen: datetime

    @staticmethod
    def create(
        ip: IPAddress,
        sources: FrozenSet[str],
        category: ThreatCategory,
        timestamp: datetime,
    ) -> ThreatIndicator:
        return ThreatIndicator(
            ip=ip,
            sources=sources,
            category=category,
            confidence=ConfidenceScore.from_source_count(len(sources)),
            first_seen=timestamp,
            last_seen=timestamp,
        )


@dataclass(frozen=True)
class SourceResult:
    """Outcome of fetching from a single threat source."""

    source_name: str
    ips: FrozenSet[IPAddress]
    error: Optional[str] = None
    from_cache: bool = False

    @property
    def is_success(self) -> bool:
        return self.error is None

    @property
    def ip_count(self) -> int:
        return len(self.ips)


@dataclass(frozen=True)
class SourceHealthRecord:
    """Persistent health state for a single source."""

    source_name: str
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    last_failure_reason: Optional[str] = None
    last_ip_count: int = 0
    consecutive_failures: int = 0
    total_runs: int = 0
    total_failures: int = 0

    def with_success(self, ip_count: int, now: datetime) -> SourceHealthRecord:
        return SourceHealthRecord(
            source_name=self.source_name,
            last_success=now,
            last_failure=self.last_failure,
            last_failure_reason=self.last_failure_reason,
            last_ip_count=ip_count,
            consecutive_failures=0,
            total_runs=self.total_runs + 1,
            total_failures=self.total_failures,
        )

    def with_failure(self, reason: str, now: datetime) -> SourceHealthRecord:
        return SourceHealthRecord(
            source_name=self.source_name,
            last_success=self.last_success,
            last_failure=now,
            last_failure_reason=reason[:500],
            last_ip_count=self.last_ip_count,
            consecutive_failures=self.consecutive_failures + 1,
            total_runs=self.total_runs + 1,
            total_failures=self.total_failures + 1,
        )

    def with_no_data(self) -> SourceHealthRecord:
        return SourceHealthRecord(
            source_name=self.source_name,
            last_success=self.last_success,
            last_failure=self.last_failure,
            last_failure_reason=self.last_failure_reason,
            last_ip_count=self.last_ip_count,
            consecutive_failures=self.consecutive_failures,
            total_runs=self.total_runs + 1,
            total_failures=self.total_failures,
        )

    @property
    def is_stale(self, threshold_days: int = 30) -> bool:
        if self.last_success is None:
            return self.total_runs > 0
        delta = datetime.now(timezone.utc) - self.last_success
        return delta.days > threshold_days

    @property
    def is_failing(self) -> bool:
        return self.consecutive_failures > 0


# ---------------------------------------------------------------------------
# Aggregate — the result of a full collection run
# ---------------------------------------------------------------------------

@dataclass
class OverlapMetrics:
    """Source overlap / deduplication analysis."""

    unique_single_source: int = 0
    found_in_multiple: int = 0
    max_source_overlap: int = 0
    avg_sources_per_ip: float = 0.0
    per_source_unique: dict = field(default_factory=dict)
    per_source_shared: dict = field(default_factory=dict)
    top_pair_overlaps: dict = field(default_factory=dict)


@dataclass(frozen=True)
class WhitelistHit:
    """A single whitelisted IP and the sources that tried to report it."""

    ip: IPAddress
    sources: FrozenSet[str]


@dataclass
class CollectionResult:
    """Aggregate root for a complete collection run."""

    timestamp: datetime
    elapsed_seconds: float
    source_results: list  # List[SourceResult]
    indicators: list  # List[ThreatIndicator]
    whitelist_hits: list = field(default_factory=list)  # List[WhitelistHit]
    overlap: OverlapMetrics = field(default_factory=OverlapMetrics)

    @property
    def whitelist_filtered_count(self) -> int:
        return len(self.whitelist_hits)

    @property
    def total_sources(self) -> int:
        return len(self.source_results)

    @property
    def successful_sources(self) -> int:
        return sum(1 for r in self.source_results if r.is_success and r.ip_count > 0)

    @property
    def failed_sources(self) -> list:
        return [r for r in self.source_results if not r.is_success]

    @property
    def success_ratio(self) -> float:
        total = self.total_sources
        return self.successful_sources / total if total > 0 else 0.0

    @property
    def ipv4_ips(self) -> list:
        return sorted({i.ip.raw for i in self.indicators
                       if i.ip.version == IPVersion.V4 and not i.ip.is_cidr})

    @property
    def ipv4_cidrs(self) -> list:
        return sorted({i.ip.raw for i in self.indicators
                       if i.ip.version == IPVersion.V4 and i.ip.is_cidr})

    @property
    def ipv6_ips(self) -> list:
        return sorted({i.ip.raw for i in self.indicators
                       if i.ip.version == IPVersion.V6 and not i.ip.is_cidr})

    @property
    def ipv6_cidrs(self) -> list:
        return sorted({i.ip.raw for i in self.indicators
                       if i.ip.version == IPVersion.V6 and i.ip.is_cidr})

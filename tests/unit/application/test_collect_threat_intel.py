"""Unit tests for CollectThreatIntelUseCase.

Use case tests mock all ports — no real HTTP, no real files.
Tests verify orchestration logic: whitelist filtering, health updates, overlap.
"""

import pytest
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from threat_intel.domain.entities import (
    IPAddress,
    SourceHealthRecord,
    WhitelistEntry,
)
from threat_intel.domain.ports import (
    HealthRepository,
    ThreatSource,
    WhitelistRepository,
)
from threat_intel.application.use_cases.collect_threat_intel import (
    CollectThreatIntelUseCase,
)
from threat_intel.infrastructure.cache.source_cache import SourceCacheRepository


class StubSource:
    """Test double for ThreatSource."""

    def __init__(self, name: str, ips: Set[IPAddress], should_fail: bool = False):
        self._name = name
        self._ips = ips
        self._should_fail = should_fail

    @property
    def name(self) -> str:
        return self._name

    @property
    def category(self) -> str:
        return "test"

    def fetch(self) -> Set[IPAddress]:
        if self._should_fail:
            raise RuntimeError("Simulated failure")
        return self._ips


class StubWhitelistRepo(WhitelistRepository):
    def __init__(self, entries: List[WhitelistEntry] = None):
        self._entries = entries or []

    def load(self) -> List[WhitelistEntry]:
        return self._entries


class StubHealthRepo(HealthRepository):
    def __init__(self):
        self.saved = None

    def load_all(self) -> Dict[str, SourceHealthRecord]:
        return {}

    def save_all(self, records: Dict[str, SourceHealthRecord]) -> None:
        self.saved = records

    def get(self, source_name: str) -> Optional[SourceHealthRecord]:
        return None


class TestCollectThreatIntelUseCase:

    @pytest.fixture(autouse=True)
    def _cache(self, tmp_path):
        self.source_cache = SourceCacheRepository(str(tmp_path / "cache"))

    def test_collects_from_all_sources(self):
        src1 = StubSource("Src1", {IPAddress.parse("1.2.3.4")})
        src2 = StubSource("Src2", {IPAddress.parse("5.6.7.8")})
        uc = CollectThreatIntelUseCase(
            sources=[src1, src2],
            whitelist_repo=StubWhitelistRepo(),
            health_repo=StubHealthRepo(),
            source_cache=self.source_cache,
        )

        result = uc.execute()

        assert result.total_sources == 2
        assert result.successful_sources == 2
        assert len(result.indicators) == 2

    def test_isolates_source_failure(self):
        src_ok = StubSource("OK", {IPAddress.parse("1.2.3.4")})
        src_fail = StubSource("Fail", set(), should_fail=True)
        uc = CollectThreatIntelUseCase(
            sources=[src_ok, src_fail],
            whitelist_repo=StubWhitelistRepo(),
            health_repo=StubHealthRepo(),
            source_cache=self.source_cache,
        )

        result = uc.execute()

        assert result.successful_sources == 1
        assert len(result.failed_sources) == 1
        assert result.failed_sources[0].source_name == "Fail"

    def test_whitelist_filters_ips(self):
        src = StubSource("Src", {
            IPAddress.parse("8.8.8.8"),
            IPAddress.parse("1.2.3.4"),
        })
        wl = StubWhitelistRepo([WhitelistEntry.parse("8.8.8.8")])
        uc = CollectThreatIntelUseCase(
            sources=[src],
            whitelist_repo=wl,
            health_repo=StubHealthRepo(),
            source_cache=self.source_cache,
        )

        result = uc.execute()

        ip_raws = {i.ip.raw for i in result.indicators}
        assert "8.8.8.8" not in ip_raws
        assert "1.2.3.4" in ip_raws

    def test_deduplication_across_sources(self):
        shared_ip = IPAddress.parse("5.5.5.5")
        src1 = StubSource("Src1", {shared_ip, IPAddress.parse("1.1.1.1")})
        src2 = StubSource("Src2", {shared_ip, IPAddress.parse("2.2.2.2")})
        uc = CollectThreatIntelUseCase(
            sources=[src1, src2],
            whitelist_repo=StubWhitelistRepo(),
            health_repo=StubHealthRepo(),
            source_cache=self.source_cache,
        )

        result = uc.execute()

        assert len(result.indicators) == 3
        shared = [i for i in result.indicators if i.ip.raw == "5.5.5.5"][0]
        assert len(shared.sources) == 2
        assert shared.confidence.value == 40

    def test_updates_health_records(self):
        health_repo = StubHealthRepo()
        src = StubSource("TestSrc", {IPAddress.parse("1.2.3.4")})
        uc = CollectThreatIntelUseCase(
            sources=[src],
            whitelist_repo=StubWhitelistRepo(),
            health_repo=health_repo,
            source_cache=self.source_cache,
        )

        uc.execute()

        assert health_repo.saved is not None
        assert "TestSrc" in health_repo.saved
        assert health_repo.saved["TestSrc"].consecutive_failures == 0
        assert health_repo.saved["TestSrc"].last_ip_count == 1

    def test_overlap_metrics_computed(self):
        ip = IPAddress.parse("1.2.3.4")
        src1 = StubSource("A", {ip})
        src2 = StubSource("B", {ip})
        uc = CollectThreatIntelUseCase(
            sources=[src1, src2],
            whitelist_repo=StubWhitelistRepo(),
            health_repo=StubHealthRepo(),
            source_cache=self.source_cache,
        )

        result = uc.execute()

        assert result.overlap.found_in_multiple == 1
        assert result.overlap.unique_single_source == 0

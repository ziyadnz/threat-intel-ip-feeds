"""Unit tests for domain services — pure logic, no I/O."""

import pytest

from threat_intel.domain.entities import (
    IPAddress,
    ThreatCategory,
    WhitelistEntry,
)
from threat_intel.domain.services import (
    IPValidator,
    IndicatorBuilder,
    OverlapAnalyzer,
    WhitelistFilter,
    resolve_category,
)
from datetime import datetime, timezone


class TestResolveCategory:
    def test_known_source(self):
        # Arrange
        sources = frozenset({"Feodo Tracker"})

        # Act
        category = resolve_category(sources)

        # Assert
        assert category == ThreatCategory.BOTNET_C2

    def test_unknown_source(self):
        # Arrange
        sources = frozenset({"SomeNewFeed"})

        # Act
        category = resolve_category(sources)

        # Assert
        assert category == ThreatCategory.UNKNOWN

    def test_multiple_sources_picks_first_alphabetically(self):
        # Arrange
        sources = frozenset({"Tor Exit Nodes", "AbuseIPDB"})

        # Act
        category = resolve_category(sources)

        # Assert — "AbuseIPDB" comes before "Tor Exit Nodes" alphabetically
        assert category == ThreatCategory.CROWD_SOURCED


class TestWhitelistFilter:
    def test_empty_whitelist_allows_everything(self):
        # Arrange
        wl = WhitelistFilter([])
        ip = IPAddress.parse("8.8.8.8")

        # Act & Assert
        assert wl.is_whitelisted(ip) is False

    def test_exact_match(self):
        # Arrange
        entry = WhitelistEntry.parse("8.8.8.8")
        wl = WhitelistFilter([entry])
        ip = IPAddress.parse("8.8.8.8")

        # Act & Assert
        assert wl.is_whitelisted(ip) is True

    def test_cidr_match(self):
        # Arrange
        entry = WhitelistEntry.parse("1.1.1.0/24")
        wl = WhitelistFilter([entry])
        ip_in = IPAddress.parse("1.1.1.50")
        ip_out = IPAddress.parse("1.1.2.1")

        # Act & Assert
        assert wl.is_whitelisted(ip_in) is True
        assert wl.is_whitelisted(ip_out) is False

    def test_filter_set_returns_kept_and_count(self):
        # Arrange
        entry = WhitelistEntry.parse("8.8.8.8")
        wl = WhitelistFilter([entry])
        ips = {IPAddress.parse("8.8.8.8"), IPAddress.parse("1.2.3.4")}

        # Act
        kept, filtered = wl.filter_set(ips)

        # Assert
        assert len(kept) == 1
        assert filtered == 1
        assert IPAddress.parse("1.2.3.4") in kept


class TestIPValidator:
    def test_valid_public_ip(self):
        # Arrange & Act
        ip = IPValidator.parse_and_validate("8.8.8.8")

        # Assert
        assert ip is not None
        assert ip.raw == "8.8.8.8"

    def test_private_ip_rejected(self):
        # Arrange & Act & Assert
        assert IPValidator.parse_and_validate("192.168.1.1") is None

    def test_invalid_string_rejected(self):
        # Arrange & Act & Assert
        assert IPValidator.parse_and_validate("not_an_ip") is None

    def test_loopback_rejected(self):
        # Arrange & Act & Assert
        assert IPValidator.parse_and_validate("127.0.0.1") is None


class TestOverlapAnalyzer:
    def test_empty_input(self):
        # Arrange & Act
        metrics = OverlapAnalyzer.analyze({}, [])

        # Assert
        assert metrics.unique_single_source == 0
        assert metrics.found_in_multiple == 0

    def test_all_unique(self):
        # Arrange
        ip_sources = {
            "1.1.1.1": frozenset({"A"}),
            "2.2.2.2": frozenset({"B"}),
        }

        # Act
        metrics = OverlapAnalyzer.analyze(ip_sources, ["A", "B"])

        # Assert
        assert metrics.unique_single_source == 2
        assert metrics.found_in_multiple == 0
        assert metrics.max_source_overlap == 1

    def test_full_overlap(self):
        # Arrange
        ip_sources = {
            "1.1.1.1": frozenset({"A", "B", "C"}),
        }

        # Act
        metrics = OverlapAnalyzer.analyze(ip_sources, ["A", "B", "C"])

        # Assert
        assert metrics.unique_single_source == 0
        assert metrics.found_in_multiple == 1
        assert metrics.max_source_overlap == 3

    def test_per_source_unique_counts(self):
        # Arrange
        ip_sources = {
            "1.1.1.1": frozenset({"A"}),
            "2.2.2.2": frozenset({"A", "B"}),
            "3.3.3.3": frozenset({"B"}),
        }

        # Act
        metrics = OverlapAnalyzer.analyze(ip_sources, ["A", "B"])

        # Assert
        assert metrics.per_source_unique["A"] == 1
        assert metrics.per_source_unique["B"] == 1
        assert metrics.per_source_shared["A"] == 1
        assert metrics.per_source_shared["B"] == 1

    def test_pair_overlap(self):
        # Arrange
        ip_sources = {
            "1.1.1.1": frozenset({"A", "B"}),
            "2.2.2.2": frozenset({"A", "B"}),
            "3.3.3.3": frozenset({"A"}),
        }

        # Act
        metrics = OverlapAnalyzer.analyze(ip_sources, ["A", "B"])

        # Assert
        assert "A & B" in metrics.top_pair_overlaps
        assert metrics.top_pair_overlaps["A & B"] == 2


class TestIndicatorBuilder:
    def test_builds_indicators(self):
        # Arrange
        now = datetime.now(timezone.utc)
        ip = IPAddress.parse("1.2.3.4")
        ip_sources = {"1.2.3.4": frozenset({"Feodo Tracker"})}
        ip_objects = {"1.2.3.4": ip}

        # Act
        indicators = IndicatorBuilder.build(ip_sources, ip_objects, now)

        # Assert
        assert len(indicators) == 1
        assert indicators[0].ip.raw == "1.2.3.4"
        assert indicators[0].category == ThreatCategory.BOTNET_C2
        assert indicators[0].confidence.value == 20

    def test_multi_source_confidence(self):
        # Arrange
        now = datetime.now(timezone.utc)
        ip = IPAddress.parse("5.5.5.5")
        ip_sources = {"5.5.5.5": frozenset({"A", "B", "C"})}
        ip_objects = {"5.5.5.5": ip}

        # Act
        indicators = IndicatorBuilder.build(ip_sources, ip_objects, now)

        # Assert
        assert indicators[0].confidence.value == 60

    def test_skips_missing_ip_objects(self):
        # Arrange
        now = datetime.now(timezone.utc)
        ip_sources = {"1.2.3.4": frozenset({"A"})}
        ip_objects = {}  # IP not in objects map

        # Act
        indicators = IndicatorBuilder.build(ip_sources, ip_objects, now)

        # Assert
        assert len(indicators) == 0

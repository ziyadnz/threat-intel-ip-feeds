"""Unit tests for domain entities and value objects.

All tests follow the AAA (Arrange-Act-Assert) pattern.
Domain tests have ZERO infrastructure dependencies — no HTTP, no files.
"""

import pytest
from datetime import datetime, timezone

from threat_intel.domain.entities import (
    ConfidenceScore,
    CollectionResult,
    IPAddress,
    IPVersion,
    OverlapMetrics,
    SourceHealthRecord,
    SourceResult,
    ThreatCategory,
    ThreatIndicator,
    WhitelistEntry,
)


class TestIPAddress:
    def test_parse_valid_ipv4(self):
        # Arrange & Act
        ip = IPAddress.parse("8.8.8.8")

        # Assert
        assert ip is not None
        assert ip.raw == "8.8.8.8"
        assert ip.version == IPVersion.V4
        assert ip.is_cidr is False

    def test_parse_valid_ipv6(self):
        # Arrange & Act
        ip = IPAddress.parse("2001:db8::1")

        # Assert
        assert ip is not None
        assert ip.version == IPVersion.V6

    def test_parse_cidr_v4(self):
        # Arrange & Act
        ip = IPAddress.parse("10.0.0.0/8")

        # Assert
        assert ip is not None
        assert ip.is_cidr is True
        assert ip.version == IPVersion.V4

    def test_parse_cidr_v6(self):
        # Arrange & Act
        ip = IPAddress.parse("2001:db8::/32")

        # Assert
        assert ip is not None
        assert ip.is_cidr is True
        assert ip.version == IPVersion.V6

    def test_parse_invalid_returns_none(self):
        # Arrange & Act & Assert
        assert IPAddress.parse("not_an_ip") is None
        assert IPAddress.parse("") is None
        assert IPAddress.parse("999.999.999.999") is None

    def test_is_public_true_for_public_ip(self):
        # Arrange
        ip = IPAddress.parse("8.8.8.8")

        # Act & Assert
        assert ip.is_public is True

    def test_is_public_false_for_private_ip(self):
        # Arrange
        ip = IPAddress.parse("192.168.1.1")

        # Act & Assert
        assert ip.is_public is False

    def test_is_public_false_for_loopback(self):
        # Arrange
        ip = IPAddress.parse("127.0.0.1")

        # Act & Assert
        assert ip.is_public is False

    def test_frozen_hashable(self):
        # Arrange
        ip1 = IPAddress.parse("8.8.8.8")
        ip2 = IPAddress.parse("8.8.8.8")

        # Act
        ip_set = {ip1, ip2}

        # Assert
        assert len(ip_set) == 1


class TestConfidenceScore:
    def test_from_single_source(self):
        # Arrange & Act
        score = ConfidenceScore.from_source_count(1)

        # Assert
        assert score.value == 20

    def test_from_multiple_sources(self):
        # Arrange & Act
        score = ConfidenceScore.from_source_count(3)

        # Assert
        assert score.value == 60

    def test_capped_at_100(self):
        # Arrange & Act
        score = ConfidenceScore.from_source_count(10)

        # Assert
        assert score.value == 100

    def test_negative_clamped_to_zero(self):
        # Arrange & Act
        score = ConfidenceScore(value=-5)

        # Assert
        assert score.value == 0


class TestWhitelistEntry:
    def test_parse_single_ip(self):
        # Arrange & Act
        entry = WhitelistEntry.parse("8.8.8.8")

        # Assert
        assert entry is not None

    def test_parse_cidr(self):
        # Arrange & Act
        entry = WhitelistEntry.parse("1.1.1.0/24")

        # Assert
        assert entry is not None

    def test_parse_invalid_returns_none(self):
        # Arrange & Act & Assert
        assert WhitelistEntry.parse("garbage") is None
        assert WhitelistEntry.parse("") is None

    def test_covers_exact_ip_match(self):
        # Arrange
        entry = WhitelistEntry.parse("8.8.8.8")
        ip = IPAddress.parse("8.8.8.8")

        # Act & Assert
        assert entry.covers(ip) is True

    def test_does_not_cover_different_ip(self):
        # Arrange
        entry = WhitelistEntry.parse("8.8.8.8")
        ip = IPAddress.parse("1.2.3.4")

        # Act & Assert
        assert entry.covers(ip) is False

    def test_cidr_covers_ip_in_range(self):
        # Arrange
        entry = WhitelistEntry.parse("1.1.1.0/24")
        ip = IPAddress.parse("1.1.1.100")

        # Act & Assert
        assert entry.covers(ip) is True

    def test_cidr_does_not_cover_ip_outside_range(self):
        # Arrange
        entry = WhitelistEntry.parse("1.1.1.0/24")
        ip = IPAddress.parse("1.1.2.1")

        # Act & Assert
        assert entry.covers(ip) is False

    def test_ipv4_cidr_does_not_cover_ipv6(self):
        # Arrange
        entry = WhitelistEntry.parse("1.1.1.0/24")
        ip = IPAddress.parse("2001:db8::1")

        # Act & Assert
        assert entry.covers(ip) is False


class TestSourceHealthRecord:
    def test_with_success_resets_failures(self):
        # Arrange
        now = datetime.now(timezone.utc)
        record = SourceHealthRecord(
            source_name="Test",
            consecutive_failures=5,
            total_runs=10,
            total_failures=5,
        )

        # Act
        updated = record.with_success(ip_count=100, now=now)

        # Assert
        assert updated.consecutive_failures == 0
        assert updated.last_success == now
        assert updated.last_ip_count == 100
        assert updated.total_runs == 11

    def test_with_failure_increments(self):
        # Arrange
        now = datetime.now(timezone.utc)
        record = SourceHealthRecord(source_name="Test")

        # Act
        updated = record.with_failure("timeout", now)

        # Assert
        assert updated.consecutive_failures == 1
        assert updated.total_failures == 1
        assert updated.last_failure_reason == "timeout"

    def test_with_failure_truncates_long_reason(self):
        # Arrange
        now = datetime.now(timezone.utc)
        record = SourceHealthRecord(source_name="Test")

        # Act
        updated = record.with_failure("x" * 1000, now)

        # Assert
        assert len(updated.last_failure_reason) == 500


class TestSourceResult:
    def test_success_result(self):
        # Arrange
        ips = frozenset({IPAddress.parse("8.8.8.8")})

        # Act
        result = SourceResult(source_name="Test", ips=ips)

        # Assert
        assert result.is_success is True
        assert result.ip_count == 1

    def test_failed_result(self):
        # Arrange & Act
        result = SourceResult(source_name="Test", ips=frozenset(), error="timeout")

        # Assert
        assert result.is_success is False
        assert result.ip_count == 0


class TestCollectionResult:
    def test_success_ratio(self):
        # Arrange
        sr_ok = SourceResult("A", frozenset({IPAddress.parse("1.2.3.4")}))
        sr_fail = SourceResult("B", frozenset(), error="timeout")

        # Act
        result = CollectionResult(
            timestamp=datetime.now(timezone.utc),
            elapsed_seconds=5.0,
            source_results=[sr_ok, sr_fail],
            indicators=[],
        )

        # Assert
        assert result.total_sources == 2
        assert result.successful_sources == 1
        assert result.success_ratio == 0.5

    def test_ipv4_separation(self):
        # Arrange
        now = datetime.now(timezone.utc)
        ip4 = IPAddress.parse("1.2.3.4")
        ip6 = IPAddress.parse("2001:db8::1")
        cidr4 = IPAddress.parse("10.0.0.0/8")

        indicators = [
            ThreatIndicator.create(ip4, frozenset({"A"}), ThreatCategory.ATTACKER, now),
            ThreatIndicator.create(ip6, frozenset({"A"}), ThreatCategory.ATTACKER, now),
            ThreatIndicator.create(cidr4, frozenset({"A"}), ThreatCategory.ATTACKER, now),
        ]

        # Act
        result = CollectionResult(
            timestamp=now, elapsed_seconds=1.0,
            source_results=[], indicators=indicators,
        )

        # Assert
        assert result.ipv4_ips == ["1.2.3.4"]
        assert result.ipv4_cidrs == ["10.0.0.0/8"]
        assert result.ipv6_ips == ["2001:db8::1"]

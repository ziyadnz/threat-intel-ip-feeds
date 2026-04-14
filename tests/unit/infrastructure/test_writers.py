"""Unit tests for output writers — CSV, STIX, raw, JSON."""

import csv
import json
import os
import pytest
from datetime import datetime, timezone

from threat_intel.domain.entities import (
    CollectionResult,
    IPAddress,
    IPVersion,
    OverlapMetrics,
    SourceResult,
    ThreatCategory,
    ThreatIndicator,
)
from threat_intel.infrastructure.writers.raw_writer import RawIPv4Writer
from threat_intel.infrastructure.writers.csv_writer import CSVWriter
from threat_intel.infrastructure.writers.stix_writer import STIXBundleWriter
from threat_intel.infrastructure.writers.json_writer import FullJSONWriter


def _make_result():
    now = datetime.now(timezone.utc)
    ip4 = IPAddress.parse("1.2.3.4")
    ip6 = IPAddress.parse("2001:db8::1")
    cidr = IPAddress.parse("10.0.0.0/8")

    indicators = [
        ThreatIndicator.create(ip4, frozenset({"Feodo Tracker"}),
                               ThreatCategory.BOTNET_C2, now),
        ThreatIndicator.create(ip6, frozenset({"Tor Exit Nodes"}),
                               ThreatCategory.ANONYMIZER, now),
        ThreatIndicator.create(cidr, frozenset({"Spamhaus DROP"}),
                               ThreatCategory.INFRASTRUCTURE, now),
    ]

    return CollectionResult(
        timestamp=now,
        elapsed_seconds=5.0,
        source_results=[
            SourceResult("Feodo Tracker", frozenset({ip4})),
            SourceResult("Tor Exit Nodes", frozenset({ip6})),
            SourceResult("Spamhaus DROP", frozenset({cidr})),
        ],
        indicators=indicators,
    )


class TestRawIPv4Writer:
    def test_writes_ips_and_cidrs_no_headers(self, tmp_path):
        # Arrange
        writer = RawIPv4Writer()
        result = _make_result()

        # Act
        path = writer.write(result, str(tmp_path))

        # Assert
        content = open(path).read()
        assert "1.2.3.4\n" in content
        assert "10.0.0.0/8\n" in content
        assert "#" not in content  # no headers


class TestCSVWriter:
    def test_csv_columns(self, tmp_path):
        # Arrange
        writer = CSVWriter()
        result = _make_result()

        # Act
        path = writer.write(result, str(tmp_path))

        # Assert
        with open(path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 3
        assert set(rows[0].keys()) == {
            "ip", "type", "is_cidr", "sources", "source_count",
            "category", "confidence", "first_seen", "last_seen",
        }

    def test_csv_source_and_category(self, tmp_path):
        # Arrange
        writer = CSVWriter()
        result = _make_result()

        # Act
        path = writer.write(result, str(tmp_path))

        # Assert
        with open(path) as f:
            reader = csv.DictReader(f)
            rows = {r["ip"]: r for r in reader}

        assert rows["1.2.3.4"]["sources"] == "Feodo Tracker"
        assert rows["1.2.3.4"]["category"] == "botnet-c2"
        assert rows["1.2.3.4"]["confidence"] == "20"


class TestSTIXBundleWriter:
    def test_bundle_structure(self, tmp_path):
        # Arrange
        writer = STIXBundleWriter()
        result = _make_result()

        # Act
        path = writer.write(result, str(tmp_path))

        # Assert
        with open(path) as f:
            bundle = json.load(f)

        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) == 4  # 1 identity + 3 indicators

    def test_identity_object(self, tmp_path):
        # Arrange
        writer = STIXBundleWriter()
        result = _make_result()

        # Act
        path = writer.write(result, str(tmp_path))

        # Assert
        with open(path) as f:
            bundle = json.load(f)

        identity = bundle["objects"][0]
        assert identity["type"] == "identity"
        assert identity["spec_version"] == "2.1"
        assert identity["identity_class"] == "system"

    def test_indicator_patterns(self, tmp_path):
        # Arrange
        writer = STIXBundleWriter()
        result = _make_result()

        # Act
        path = writer.write(result, str(tmp_path))

        # Assert
        with open(path) as f:
            bundle = json.load(f)

        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        patterns = {i["pattern"] for i in indicators}
        assert "[ipv4-addr:value = '1.2.3.4']" in patterns
        assert "[ipv6-addr:value = '2001:db8::1']" in patterns

    def test_confidence_from_source_count(self, tmp_path):
        # Arrange
        writer = STIXBundleWriter()
        now = datetime.now(timezone.utc)
        ip = IPAddress.parse("5.5.5.5")
        indicator = ThreatIndicator.create(
            ip, frozenset({"A", "B", "C"}), ThreatCategory.ATTACKER, now,
        )
        result = CollectionResult(
            timestamp=now, elapsed_seconds=1.0,
            source_results=[], indicators=[indicator],
        )

        # Act
        path = writer.write(result, str(tmp_path))

        # Assert
        with open(path) as f:
            bundle = json.load(f)

        ind = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
        assert ind["confidence"] == 60


class TestFullJSONWriter:
    def test_json_structure(self, tmp_path):
        # Arrange
        writer = FullJSONWriter()
        result = _make_result()

        # Act
        path = writer.write(result, str(tmp_path))

        # Assert
        with open(path) as f:
            data = json.load(f)

        assert "timestamp" in data
        assert "ipv4" in data
        assert "ipv6" in data
        assert "sources" in data
        assert data["total_sources"] == 3
        assert data["successful_sources"] == 3

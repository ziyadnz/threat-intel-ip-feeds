"""STIX 2.1 JSON bundle output writer."""

from __future__ import annotations

import json
import os
import uuid

from threat_intel.domain.entities import CollectionResult, IPVersion
from threat_intel.domain.ports import OutputWriter


class STIXBundleWriter(OutputWriter):
    """Writes stix_bundle.json — STIX 2.1 compliant indicator bundle."""

    IDENTITY_SEED = "https://github.com/ziyadnz/threat-intel-ip-feeds"

    @property
    def format_name(self) -> str:
        return "STIX 2.1"

    def write(self, result: CollectionResult, output_dir: str) -> str:
        path = os.path.join(output_dir, "stix_bundle.json")
        os.makedirs(output_dir, exist_ok=True)

        timestamp = result.timestamp.isoformat()
        identity_id = "identity--" + str(
            uuid.uuid5(uuid.NAMESPACE_URL, self.IDENTITY_SEED)
        )

        objects = [self._build_identity(identity_id, timestamp)]

        for indicator in result.indicators:
            objects.append(
                self._build_indicator(indicator, identity_id, timestamp)
            )

        bundle = {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid5(uuid.NAMESPACE_URL, timestamp)),
            "objects": objects,
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2, ensure_ascii=False)

        return path

    @staticmethod
    def _build_identity(identity_id: str, timestamp: str) -> dict:
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": timestamp,
            "modified": timestamp,
            "name": "Threat Intel IP Feeds Aggregator",
            "identity_class": "system",
        }

    @staticmethod
    def _build_indicator(indicator, identity_id: str, timestamp: str) -> dict:
        ip = indicator.ip
        addr_type = "ipv4-addr" if ip.version == IPVersion.V4 else "ipv6-addr"
        pattern = f"[{addr_type}:value = '{ip.raw}']"

        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_URL, ip.raw)),
            "created": timestamp,
            "modified": timestamp,
            "name": f"Malicious IP: {ip.raw}",
            "description": (
                f"Reported by {len(indicator.sources)} source(s): "
                f"{', '.join(sorted(indicator.sources))}. "
                f"Category: {indicator.category.value}."
            ),
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": timestamp,
            "labels": [indicator.category.value] + sorted(indicator.sources),
            "created_by_ref": identity_id,
            "confidence": indicator.confidence.value,
        }

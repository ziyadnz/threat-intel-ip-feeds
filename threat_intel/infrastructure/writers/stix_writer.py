"""STIX 2.1 JSON bundle output writer.

Optimized for size: compact JSON (no indentation), minimal indicator fields.
Full STIX 2.1 compliance maintained — only optional fields removed.
"""

from __future__ import annotations

import json
import hashlib
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

        previous = {}
        identity = self._build_identity(identity_id, timestamp)
        try:
            with open(path, encoding="utf-8") as f:
                old_objects = json.load(f)["objects"]
                previous = {obj["id"]: obj for obj in old_objects}
                old_identity = old_objects[0]
            if old_identity.get("id") == identity_id:
                identity["created"] = old_identity["created"]
                identity["modified"] = old_identity.get("modified", old_identity["created"])
        except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError):
            pass
        objects = [identity]

        for indicator in sorted(result.indicators, key=lambda i: i.ip.raw):
            obj = self._build_indicator(indicator, identity_id, timestamp)
            old = previous.get(obj["id"])
            if old:
                obj["created"] = old.get("created", obj["created"])
                obj["valid_from"] = old.get("valid_from", obj["valid_from"])
                obj["modified"] = old.get("modified", obj["created"])
                if any(old.get(key) != value for key, value in obj.items() if key != "modified"):
                    obj["modified"] = timestamp
            objects.append(obj)

        content_hash = hashlib.sha256(json.dumps(objects, sort_keys=True).encode()).hexdigest()
        bundle = {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid5(uuid.NAMESPACE_URL, content_hash)),
            "objects": objects,
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, ensure_ascii=False, separators=(",", ":"))

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

        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_URL, ip.raw)),
            "created_by_ref": identity_id,
            "pattern": f"[{addr_type}:value = '{ip.raw}']",
            "pattern_type": "stix",
            "created": indicator.first_seen.isoformat(),
            "modified": indicator.first_seen.isoformat(),
            "valid_from": indicator.first_seen.isoformat(),
            "indicator_types": ["malicious-activity"],
            "confidence": indicator.confidence.value,
            "labels": [indicator.category.value],
        }

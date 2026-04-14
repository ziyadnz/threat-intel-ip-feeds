"""CSV output writer — per-IP metadata for SIEM enrichment."""

from __future__ import annotations

import csv
import os

from threat_intel.domain.entities import CollectionResult
from threat_intel.domain.ports import OutputWriter


class CSVWriter(OutputWriter):
    """Writes blacklist.csv with per-IP metadata columns."""

    @property
    def format_name(self) -> str:
        return "CSV"

    def write(self, result: CollectionResult, output_dir: str) -> str:
        path = os.path.join(output_dir, "blacklist.csv")
        os.makedirs(output_dir, exist_ok=True)

        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "ip", "type", "is_cidr", "sources", "source_count",
                "category", "confidence", "first_seen", "last_seen",
            ])

            for indicator in sorted(result.indicators, key=lambda i: i.ip.raw):
                writer.writerow([
                    indicator.ip.raw,
                    indicator.ip.version.value,
                    indicator.ip.is_cidr,
                    "|".join(sorted(indicator.sources)),
                    len(indicator.sources),
                    indicator.category.value,
                    indicator.confidence.value,
                    indicator.first_seen.isoformat(),
                    indicator.last_seen.isoformat(),
                ])

        return path

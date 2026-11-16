"""Full JSON dataset output writer."""

from __future__ import annotations

import json
import os

from threat_intel.domain.entities import CollectionResult
from threat_intel.domain.ports import OutputWriter


class FullJSONWriter(OutputWriter):
    """Writes blacklist_full.json with complete run metadata."""

    @property
    def format_name(self) -> str:
        return "Full JSON"

    def write(self, result: CollectionResult, output_dir: str) -> str:
        path = os.path.join(output_dir, "blacklist_full.json")
        os.makedirs(output_dir, exist_ok=True)

        data = {
            "timestamp": result.timestamp.isoformat(),
            "elapsed_seconds": result.elapsed_seconds,
            "total_sources": result.total_sources,
            "successful_sources": result.successful_sources,
            "whitelist_filtered": result.whitelist_filtered_count,
            "whitelist_details": {
                hit.ip.raw: sorted(hit.sources)
                for hit in result.whitelist_hits
            },
            "sources": {
                sr.source_name: sr.ip_count
                for sr in sorted(result.source_results, key=lambda r: r.source_name)
            },
            "source_details": {
                sr.source_name: {
                    "ip_count": sr.ip_count,
                    "from_cache": sr.from_cache,
                    "partial": sr.partial,
                    "skipped": sr.skipped,
                    "error": sr.error,
                    "cache_reason": sr.cache_reason,
                    "observed_at": sr.observed_at.isoformat() if sr.observed_at else None,
                    "elapsed_seconds": sr.elapsed_seconds,
                }
                for sr in sorted(result.source_results, key=lambda r: r.source_name)
            },
            "failures": {
                sr.source_name: sr.error
                for sr in sorted(result.source_results, key=lambda r: r.source_name)
                if not sr.is_success
            },
            "overlap": {
                "unique_single_source": result.overlap.unique_single_source,
                "found_in_multiple": result.overlap.found_in_multiple,
                "max_source_overlap": result.overlap.max_source_overlap,
                "avg_sources_per_ip": result.overlap.avg_sources_per_ip,
            },
            "ipv4": {
                "ips": result.ipv4_ips,
                "cidrs": result.ipv4_cidrs,
            },
            "ipv6": {
                "ips": result.ipv6_ips,
                "cidrs": result.ipv6_cidrs,
            },
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)

        return path

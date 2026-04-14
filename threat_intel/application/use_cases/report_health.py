"""Use case: Generate health report and notify on failures.

Reads health state, generates markdown report, and decides whether
to open/close GitHub issues based on current health status.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List

from threat_intel.domain.entities import (
    CollectionResult,
    SourceHealthRecord,
)
from threat_intel.domain.ports import HealthRepository, Notifier, ReportWriter

logger = logging.getLogger(__name__)


class ReportHealthUseCase:
    """Generates health report and triggers notifications as needed."""

    def __init__(
        self,
        health_repo: HealthRepository,
        report_writer: ReportWriter,
        notifier: Notifier,
        output_dir: str,
        stale_threshold_days: int = 30,
    ):
        self._health_repo = health_repo
        self._report_writer = report_writer
        self._notifier = notifier
        self._output_dir = output_dir
        self._stale_days = stale_threshold_days

    def execute(self, result: CollectionResult) -> str:
        """Generate report, send notifications. Returns report text."""
        health = self._health_repo.load_all()

        stale = self._find_stale(health)
        failing = self._find_failing(health)
        failures = result.failed_sources

        report = self._build_report(result, failures, stale, failing)

        self._report_writer.write(report, self._output_dir)

        if failures or stale or failing:
            title = f"Source Health Alert - {result.timestamp.strftime('%Y-%m-%d')}"
            if failures:
                title = f"[{len(failures)} FAILED] {title}"
            self._notifier.notify(title, report)
        else:
            self._notifier.close_resolved()

        return report

    def _find_stale(self, health: dict) -> List[SourceHealthRecord]:
        now = datetime.now(timezone.utc)
        stale = []
        for record in health.values():
            if record.last_success is None and record.total_runs > 0:
                stale.append(record)
            elif record.last_success is not None:
                days = (now - record.last_success).days
                if days > self._stale_days:
                    stale.append(record)
        return stale

    @staticmethod
    def _find_failing(health: dict) -> List[SourceHealthRecord]:
        return sorted(
            [r for r in health.values() if r.is_failing],
            key=lambda r: -r.consecutive_failures,
        )

    def _build_report(self, result, failures, stale, failing) -> str:
        lines = [
            "# IP Blacklist Aggregator - Health Report",
            "",
            f"**Date:** {result.timestamp.isoformat()}",
            f"**Duration:** {result.elapsed_seconds}s",
            f"**Successful:** {result.successful_sources}/{result.total_sources}",
        ]
        if result.whitelist_filtered_count > 0:
            lines.append(
                f"**Whitelist Filtered:** {result.whitelist_filtered_count}"
            )
        lines.append("")

        if failures:
            lines += [
                "## Failed Sources This Run", "",
                "| Source | Error |",
                "|--------|------|",
            ]
            for sr in failures:
                lines.append(f"| {sr.source_name} | {(sr.error or '')[:200]} |")
            lines.append("")

        # Overlap metrics
        o = result.overlap
        if o.unique_single_source or o.found_in_multiple:
            lines += [
                "## Deduplication & Source Overlap", "",
                "| Metric | Value |",
                "|--------|-------|",
                f"| Unique to single source | {o.unique_single_source:,} |",
                f"| Found in multiple sources | {o.found_in_multiple:,} |",
                f"| Max source overlap | {o.max_source_overlap} |",
                f"| Avg sources per IP | {o.avg_sources_per_ip} |",
                "",
            ]

            if o.per_source_unique:
                lines += [
                    "### Per-Source Contribution", "",
                    "| Source | Unique | Shared | Unique % |",
                    "|--------|--------|--------|----------|",
                ]
                for src in sorted(o.per_source_unique,
                                  key=lambda s: -(o.per_source_unique.get(s, 0))):
                    u = o.per_source_unique.get(src, 0)
                    s = o.per_source_shared.get(src, 0)
                    t = u + s
                    pct = f"{u / t * 100:.1f}%" if t > 0 else "N/A"
                    lines.append(f"| {src} | {u:,} | {s:,} | {pct} |")
                lines.append("")

            if o.top_pair_overlaps:
                lines += [
                    "### Top Source Pair Overlaps", "",
                    "| Pair | Shared IPs |",
                    "|------|-----------|",
                ]
                for pair, count in o.top_pair_overlaps.items():
                    lines.append(f"| {pair} | {count:,} |")
                lines.append("")

        if stale:
            lines += [
                f"## {len(stale)} Sources Stale (30+ days)", "",
                "| Source | Last Success | Consecutive Failures |",
                "|--------|-------------|---------------------|",
            ]
            for r in stale:
                ls = r.last_success.strftime("%Y-%m-%d") if r.last_success else "Never"
                lines.append(f"| {r.source_name} | {ls} | {r.consecutive_failures} |")
            lines.append("")

        if failing:
            lines += [
                "## Consecutively Failing Sources", "",
                "| Source | Failures | Last Failure | Reason |",
                "|--------|----------|-------------|--------|",
            ]
            for r in failing:
                lf = r.last_failure.strftime("%Y-%m-%d") if r.last_failure else "?"
                reason = (r.last_failure_reason or "Unknown")[:60]
                lines.append(
                    f"| {r.source_name} | {r.consecutive_failures} | {lf} | {reason} |"
                )
            lines.append("")

        # Per-source summary table
        lines += [
            "## All Sources", "",
            "| Source | IPs | Status |",
            "|--------|-----|--------|",
        ]
        failed_names = {sr.source_name for sr in failures}
        for sr in sorted(result.source_results, key=lambda s: -s.ip_count):
            if sr.source_name in failed_names:
                status = "FAILED"
            elif sr.ip_count > 0:
                status = "OK"
            else:
                status = "EMPTY"
            lines.append(f"| {sr.source_name} | {sr.ip_count:,} | {status} |")
        lines.append("")

        if not failures and not stale and not failing:
            lines += ["## All sources healthy.", ""]

        return "\n".join(lines)

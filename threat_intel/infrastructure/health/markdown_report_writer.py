"""Health report writer — saves markdown report to disk."""

from __future__ import annotations

import logging
import os

from threat_intel.domain.ports import ReportWriter

logger = logging.getLogger(__name__)


class MarkdownReportWriter(ReportWriter):
    """Writes health report as a markdown file."""

    def write(self, content: str, output_dir: str) -> str:
        path = os.path.join(output_dir, "health_report.md")
        os.makedirs(output_dir, exist_ok=True)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            logger.info(f"Health report written: {path}")
        except OSError as e:
            logger.error(f"Health report write failed: {e}")
        return path

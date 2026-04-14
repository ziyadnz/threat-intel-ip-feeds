"""Use case: Write collection results to all configured output formats.

Implements rollback protection — refuses to write if success ratio is too low.
"""

from __future__ import annotations

import logging
from typing import List

from threat_intel.domain.entities import CollectionResult
from threat_intel.domain.ports import OutputWriter

logger = logging.getLogger(__name__)


class WriteOutputsUseCase:
    """Writes results to all output formats with rollback protection."""

    def __init__(
        self,
        writers: List[OutputWriter],
        output_dir: str,
        min_success_ratio: float = 0.2,
    ):
        self._writers = writers
        self._output_dir = output_dir
        self._min_success_ratio = min_success_ratio

    def execute(self, result: CollectionResult) -> bool:
        """Write outputs. Returns True if written, False if rolled back."""

        if result.successful_sources == 0:
            logger.critical(
                "ALL SOURCES FAILED. Preserving existing output files."
            )
            return False

        if result.success_ratio < self._min_success_ratio:
            logger.critical(
                f"Success ratio too low: "
                f"{result.successful_sources}/{result.total_sources} "
                f"({result.success_ratio:.0%}). "
                f"Threshold: {self._min_success_ratio:.0%}. "
                f"Preserving existing files."
            )
            return False

        for writer in self._writers:
            try:
                path = writer.write(result, self._output_dir)
                logger.info(f"[{writer.format_name}] Written: {path}")
            except Exception as e:
                logger.error(
                    f"[{writer.format_name}] Write failed: {e}"
                )

        return True

"""Unit tests for WriteOutputsUseCase — rollback logic."""

import pytest
from datetime import datetime, timezone

from threat_intel.domain.entities import (
    CollectionResult,
    IPAddress,
    SourceResult,
    ThreatCategory,
    ThreatIndicator,
)
from threat_intel.domain.ports import OutputWriter
from threat_intel.application.use_cases.write_outputs import WriteOutputsUseCase


class SpyWriter(OutputWriter):
    """Test double that records whether write() was called."""

    def __init__(self):
        self.written = False
        self.last_output_dir = None

    @property
    def format_name(self) -> str:
        return "Spy"

    def write(self, result: CollectionResult, output_dir: str) -> str:
        self.written = True
        self.last_output_dir = output_dir
        return f"{output_dir}/spy.txt"


def _make_result(successful: int = 5, total: int = 10):
    """Helper to create a CollectionResult with specific success/total."""
    results = []
    for i in range(successful):
        results.append(SourceResult(f"OK-{i}", frozenset({IPAddress.parse(f"1.2.3.{i}")})))
    for i in range(total - successful):
        results.append(SourceResult(f"Fail-{i}", frozenset(), error="timeout"))
    return CollectionResult(
        timestamp=datetime.now(timezone.utc),
        elapsed_seconds=5.0,
        source_results=results,
        indicators=[],
    )


class TestWriteOutputsUseCase:
    def test_writes_when_above_threshold(self):
        # Arrange
        writer = SpyWriter()
        uc = WriteOutputsUseCase(
            writers=[writer],
            output_dir="/tmp/test",
            min_success_ratio=0.2,
        )
        result = _make_result(successful=5, total=10)

        # Act
        wrote = uc.execute(result)

        # Assert
        assert wrote is True
        assert writer.written is True

    def test_rollback_when_all_failed(self):
        # Arrange
        writer = SpyWriter()
        uc = WriteOutputsUseCase(
            writers=[writer],
            output_dir="/tmp/test",
            min_success_ratio=0.2,
        )
        result = _make_result(successful=0, total=10)

        # Act
        wrote = uc.execute(result)

        # Assert
        assert wrote is False
        assert writer.written is False

    def test_rollback_below_threshold(self):
        # Arrange
        writer = SpyWriter()
        uc = WriteOutputsUseCase(
            writers=[writer],
            output_dir="/tmp/test",
            min_success_ratio=0.2,
        )
        result = _make_result(successful=1, total=10)  # 10% < 20%

        # Act
        wrote = uc.execute(result)

        # Assert
        assert wrote is False
        assert writer.written is False

    def test_writes_all_formats(self):
        # Arrange
        writer1 = SpyWriter()
        writer2 = SpyWriter()
        uc = WriteOutputsUseCase(
            writers=[writer1, writer2],
            output_dir="/tmp/test",
            min_success_ratio=0.2,
        )
        result = _make_result(successful=5, total=10)

        # Act
        uc.execute(result)

        # Assert
        assert writer1.written is True
        assert writer2.written is True

"""Health repository backed by a JSON file on disk."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Dict, Optional

from threat_intel.domain.entities import SourceHealthRecord
from threat_intel.domain.ports import HealthRepository

logger = logging.getLogger(__name__)


class JsonHealthRepository(HealthRepository):
    """Persists source health records as a JSON file."""

    def __init__(self, filepath: str):
        self._filepath = filepath

    def load_all(self) -> Dict[str, SourceHealthRecord]:
        if not os.path.exists(self._filepath):
            return {}
        try:
            with open(self._filepath, "r", encoding="utf-8") as f:
                raw = json.load(f)
            return {
                name: self._deserialize(name, data)
                for name, data in raw.items()
            }
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Health file unreadable, starting fresh: {e}")
            return {}

    def save_all(self, records: Dict[str, SourceHealthRecord]) -> None:
        os.makedirs(os.path.dirname(self._filepath), exist_ok=True)
        tmp = self._filepath + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                data = {
                    name: self._serialize(record)
                    for name, record in records.items()
                }
                json.dump(data, f, indent=2, ensure_ascii=False)
            os.replace(tmp, self._filepath)
        except OSError as e:
            logger.error(f"Health file write failed: {e}")

    def get(self, source_name: str) -> Optional[SourceHealthRecord]:
        all_records = self.load_all()
        return all_records.get(source_name)

    @staticmethod
    def _serialize(record: SourceHealthRecord) -> dict:
        return {
            "last_success": record.last_success.isoformat() if record.last_success else None,
            "last_failure": record.last_failure.isoformat() if record.last_failure else None,
            "last_failure_reason": record.last_failure_reason,
            "last_ip_count": record.last_ip_count,
            "consecutive_failures": record.consecutive_failures,
            "total_runs": record.total_runs,
            "total_failures": record.total_failures,
        }

    @staticmethod
    def _deserialize(name: str, data: dict) -> SourceHealthRecord:
        def parse_dt(val):
            if val is None:
                return None
            try:
                return datetime.fromisoformat(val)
            except (ValueError, TypeError):
                return None

        return SourceHealthRecord(
            source_name=name,
            last_success=parse_dt(data.get("last_success")),
            last_failure=parse_dt(data.get("last_failure")),
            last_failure_reason=data.get("last_failure_reason"),
            last_ip_count=data.get("last_ip_count", 0),
            consecutive_failures=data.get("consecutive_failures", 0),
            total_runs=data.get("total_runs", 0),
            total_failures=data.get("total_failures", 0),
        )

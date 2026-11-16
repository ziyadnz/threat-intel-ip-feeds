"""Source-level IP cache — persists last successful fetch per source.

Stores each source's IPs as a JSON file under a cache directory.
Used by the collection use case to serve stale data when a source is unreachable.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Set

from threat_intel.domain.entities import IPAddress, SourceResult

logger = logging.getLogger(__name__)


def _safe_filename(source_name: str) -> str:
    """Convert source name to a safe filename."""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", source_name).lower()


class SourceCacheRepository:
    """JSON-file-based cache: one file per source under cache_dir."""

    def __init__(self, cache_dir: str):
        self._cache_dir = cache_dir
        os.makedirs(self._cache_dir, exist_ok=True)

    def _path(self, source_name: str) -> str:
        return os.path.join(self._cache_dir, f"{_safe_filename(source_name)}.json")

    def save(self, source_name: str, ips: Set[IPAddress]) -> None:
        path = self._path(source_name)
        try:
            data = {
                "source": source_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "count": len(ips),
                "ips": sorted(ip.raw for ip in ips),
            }
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, path)
        except OSError as e:
            logger.warning(f"[Cache] Save failed for {source_name}: {e}")
            try:
                os.unlink(path + ".tmp")
            except OSError:
                pass

    def load(self, source_name: str) -> Set[IPAddress]:
        return set(self.load_result(source_name).ips)

    def load_result(self, source_name: str) -> SourceResult:
        path = self._path(source_name)
        result = set()
        observed_at = None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for raw in data.get("ips", []):
                ip = IPAddress.parse(raw)
                if ip:
                    result.add(ip)
            observed_at = datetime.fromisoformat(data["timestamp"])
            if observed_at.tzinfo is None or observed_at > datetime.now(timezone.utc):
                observed_at = None
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as e:
            logger.warning("[Cache] Cannot fully load %s: %s", source_name, e)
        return SourceResult(source_name, frozenset(result), from_cache=bool(result),
                            observed_at=observed_at)

    def has_cache(self, source_name: str) -> bool:
        return os.path.exists(self._path(source_name))

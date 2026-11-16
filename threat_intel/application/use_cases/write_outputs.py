"""Stage and validate outputs before replacing the last published feeds."""

from __future__ import annotations

import csv
import logging
import json
import os
import shutil
import tempfile
import time
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import List

from threat_intel.domain.entities import CollectionResult
from threat_intel.domain.ports import OutputWriter

logger = logging.getLogger(__name__)


class WriteOutputsUseCase:
    def __init__(self, writers: List[OutputWriter], output_dir: str,
                 min_success_ratio: float = 0.2):
        self._writers = writers
        self._output_dir = output_dir
        self._min_success_ratio = min_success_ratio

    def _restore_observation_times(self, result):
        """Keep first_seen across runs; cached data does not advance last_seen."""
        previous = {}
        try:
            with open(os.path.join(self._output_dir, "blacklist.csv"), newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    try:
                        first = datetime.fromisoformat(row["first_seen"])
                        last = datetime.fromisoformat(row["last_seen"])
                        if first.tzinfo and last.tzinfo and first <= last <= result.timestamp:
                            previous[row["ip"]] = first, last
                    except (ValueError, KeyError, TypeError):
                        continue
        except (OSError, csv.Error):
            pass
        fresh = {r.source_name for r in result.source_results
                 if r.is_success and not r.from_cache and not r.skipped}
        observed = {r.source_name: r.observed_at for r in result.source_results
                    if not r.partial and r.observed_at is not None and r.observed_at <= result.timestamp}
        indicators = []
        for indicator in result.indicators:
            # For a newly published cached IP, use the known cache observation time.
            fallback = max((observed[s] for s in indicator.sources if s in observed),
                           default=result.timestamp)
            first, last = previous.get(indicator.ip.raw, (fallback, fallback))
            if indicator.sources & fresh:
                last = result.timestamp
            indicators.append(replace(indicator, first_seen=first, last_seen=last))
        return replace(result, indicators=sorted(indicators, key=lambda i: i.ip.raw))

    def execute(self, result: CollectionResult) -> bool:
        if result.successful_sources == 0 or result.success_ratio < self._min_success_ratio:
            logger.critical("Success ratio too low (%s/%s); preserving feeds",
                            result.successful_sources, result.total_sources)
            return False
        started = time.perf_counter()
        output = Path(self._output_dir)
        output.mkdir(parents=True, exist_ok=True)
        result = self._restore_observation_times(result)
        # Same filesystem for atomic individual-file replacement. No cache/state files
        # are included in staging, so an output failure cannot publish staged debris.
        with tempfile.TemporaryDirectory(prefix=".feeds-", dir=output.parent) as root:
            stage = Path(root) / "stage"
            backup = Path(root) / "backup"
            stage.mkdir()
            backup.mkdir()
            previous_stix = output / "stix_bundle.json"
            if previous_stix.exists() and any(w.format_name == "STIX 2.1" for w in self._writers):
                shutil.copy2(previous_stix, stage / previous_stix.name)
            try:
                for writer in self._writers:
                    path = writer.write(result, str(stage))
                    logger.info("[%s] Staged: %s", writer.format_name, path)
                self._validate(stage, result)
            except Exception:
                logger.exception("Output staging failed; preserving published feeds")
                return False
            files = sorted(p for p in stage.iterdir() if p.is_file())
            changed = []
            try:
                for path in files:
                    destination = output / path.name
                    if destination.exists() and self._same_content(path, destination):
                        continue
                    existed = destination.exists()
                    if existed:
                        shutil.copy2(destination, backup / path.name)
                    os.replace(path, destination)
                    changed.append((destination, existed))
            except OSError:
                logger.exception("Publishing failed; restoring replaced files")
                for destination, existed in reversed(changed):
                    if existed:
                        os.replace(backup / destination.name, destination)
                    else:
                        destination.unlink(missing_ok=True)
                return False
        logger.info("Timing: output staging/publishing %.2fs (%s files changed)",
                    time.perf_counter() - started, len(changed))
        return True

    def _validate(self, stage, result):
        expected = {
            "Raw IPv4": "hourlyIPv4.txt", "Annotated IPv4": "ipv4_blacklist.txt",
            "Annotated IPv6": "ipv6_blacklist.txt", "CSV": "blacklist.csv",
            "STIX 2.1": "stix_bundle.json", "Full JSON": "blacklist_full.json",
        }
        for writer in self._writers:
            name = expected.get(writer.format_name)
            if name is not None and not (stage / name).is_file():
                raise ValueError(f"Missing required output: {name}")
        for name in ("stix_bundle.json", "blacklist_full.json"):
            path = stage / name
            if not path.exists():
                continue
            with path.open(encoding="utf-8") as f:
                data = json.load(f)
            if name == "stix_bundle.json":
                if data.get("type") != "bundle" or len(data["objects"]) != len(result.indicators) + 1:
                    raise ValueError("Incomplete STIX bundle")
            else:
                count = sum(len(data[v][k]) for v in ("ipv4", "ipv6") for k in ("ips", "cidrs"))
                if count != len(result.indicators):
                    raise ValueError("Incomplete JSON dataset")
        path = stage / "blacklist.csv"
        if path.exists():
            with path.open(newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                if not {"ip", "first_seen", "last_seen"}.issubset(reader.fieldnames or []):
                    raise ValueError("Missing CSV columns")
                if sum(1 for row in reader) != len(result.indicators):
                    raise ValueError("Incomplete CSV dataset")

    @staticmethod
    def _same_content(left, right):
        if left.stat().st_size != right.stat().st_size:
            return False
        with left.open("rb") as a, right.open("rb") as b:
            while chunk := a.read(1024 * 1024):
                if chunk != b.read(1024 * 1024):
                    return False
        return True

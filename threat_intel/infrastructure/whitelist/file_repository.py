"""Whitelist repository backed by a text file."""

from __future__ import annotations

import logging
import os
from typing import List

from threat_intel.domain.entities import WhitelistEntry
from threat_intel.domain.ports import WhitelistRepository

logger = logging.getLogger(__name__)


class FileWhitelistRepository(WhitelistRepository):
    """Loads whitelist entries from a plain-text file."""

    def __init__(self, filepath: str):
        self._filepath = filepath

    def load(self) -> List[WhitelistEntry]:
        if not os.path.exists(self._filepath):
            return []

        entries = []
        try:
            with open(self._filepath, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.split("#")[0].strip()
                    if not line:
                        continue
                    entry = WhitelistEntry.parse(line)
                    if entry is not None:
                        entries.append(entry)
                    else:
                        logger.warning(
                            f"Whitelist line {line_num} invalid: '{line}'"
                        )
        except OSError as e:
            logger.error(f"Whitelist file unreadable: {e}")

        return entries

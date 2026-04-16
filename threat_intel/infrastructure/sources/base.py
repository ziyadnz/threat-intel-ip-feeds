"""Base class for text-based threat sources.

Most sources follow the same pattern: async HTTP GET a text file, extract IPs.
This base class encodes that pattern; subclasses override parsing.
"""

from __future__ import annotations

import re
from typing import Set

from threat_intel.domain.entities import IPAddress
from threat_intel.domain.ports import HttpClient, ThreatSource
from threat_intel.domain.services import IPValidator

IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)


class TextListSource(ThreatSource):
    """Base for sources that are plain-text IP lists (one per line)."""

    def __init__(self, http: HttpClient, source_name: str,
                 url: str, source_category: str = "unknown"):
        self._http = http
        self._name = source_name
        self._url = url
        self._category = source_category

    @property
    def name(self) -> str:
        return self._name

    @property
    def category(self) -> str:
        return self._category

    def fetch(self) -> Set[IPAddress]:
        text = self._http.get(self._url)
        return self._parse(text)

    def _parse(self, text: str) -> Set[IPAddress]:
        """Default: extract all valid public IPv4 addresses via regex."""
        result = set()
        for match in IPV4_PATTERN.findall(text):
            ip = IPValidator.parse_and_validate(match)
            if ip is not None:
                result.add(ip)
        return result

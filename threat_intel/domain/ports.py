"""Domain ports (interfaces).

These abstract base classes define what the domain NEEDS from the outside world.
Infrastructure adapters implement them. The dependency arrow always points inward:
infrastructure depends on domain, never the reverse.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set

from threat_intel.domain.entities import (
    CollectionResult,
    IPAddress,
    SourceHealthRecord,
    SourceResult,
    WhitelistEntry,
)


class ThreatSource(ABC):
    """Port: fetches malicious IPs from a single threat intelligence feed."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique human-readable name for this source."""

    @property
    def category(self) -> str:
        return "unknown"

    @abstractmethod
    def fetch(self) -> Set[IPAddress]:
        """Fetch and return validated IPs. Raises on unrecoverable failure."""


class HttpClient(ABC):
    """Port: performs HTTP requests with retry semantics."""

    @abstractmethod
    def get(self, url: str, headers: Optional[Dict] = None,
            timeout: int = 60) -> str:
        """GET request, return response body text. Raises on failure."""

    @abstractmethod
    def get_json(self, url: str, headers: Optional[Dict] = None,
                 timeout: int = 60) -> object:
        """GET request, return parsed JSON. Raises on failure."""

    def close(self) -> None:
        """Release underlying resources (connection pool, session)."""


class OutputWriter(ABC):
    """Port: writes collection results in a specific format."""

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Human-readable name of the output format."""

    @abstractmethod
    def write(self, result: CollectionResult, output_dir: str) -> str:
        """Write output and return the file path written."""


class HealthRepository(ABC):
    """Port: persists and retrieves per-source health records."""

    @abstractmethod
    def load_all(self) -> Dict[str, SourceHealthRecord]:
        """Load all source health records."""

    @abstractmethod
    def save_all(self, records: Dict[str, SourceHealthRecord]) -> None:
        """Persist all source health records atomically."""

    @abstractmethod
    def get(self, source_name: str) -> Optional[SourceHealthRecord]:
        """Get health record for a specific source."""


class WhitelistRepository(ABC):
    """Port: loads whitelist entries from a persistent store."""

    @abstractmethod
    def load(self) -> List[WhitelistEntry]:
        """Load and parse all whitelist entries."""


class Notifier(ABC):
    """Port: sends alerts when source health issues are detected."""

    @abstractmethod
    def notify(self, title: str, body: str) -> None:
        """Send a notification/alert."""

    @abstractmethod
    def close_resolved(self) -> None:
        """Close previously opened alerts that are no longer relevant."""


class ReportWriter(ABC):
    """Port: writes the health/status report."""

    @abstractmethod
    def write(self, content: str, output_dir: str) -> str:
        """Write report content and return file path."""

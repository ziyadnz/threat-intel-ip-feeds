"""Unit tests for source adapters with async fake HTTP client."""

import pytest
from typing import Dict, Optional, Set

from threat_intel.domain.entities import IPAddress
from threat_intel.domain.ports import HttpClient
from threat_intel.infrastructure.sources.global_sources import (
    BinaryDefenseSource,
    BlocklistDeSource,
    CinsArmySource,
    FeodoTrackerSource,
    GreenSnowSource,
    SpamhausDropSource,
    StamparmIpsumSource,
    TorExitSource,
)


class FakeHttpClient(HttpClient):
    """Async test double that returns pre-configured responses."""

    def __init__(self, text_responses: Dict[str, str] = None,
                 json_responses: Dict[str, object] = None):
        self._texts = text_responses or {}
        self._jsons = json_responses or {}

    async def get(self, url: str, headers: Optional[Dict] = None,
                  timeout: int = 60) -> str:
        for pattern, body in self._texts.items():
            if pattern in url:
                return body
        raise RuntimeError(f"No fake response for {url}")

    async def get_json(self, url: str, headers: Optional[Dict] = None,
                       timeout: int = 60) -> object:
        for pattern, data in self._jsons.items():
            if pattern in url:
                return data
        raise RuntimeError(f"No fake JSON response for {url}")


class TestSpamhausDropSource:
    @pytest.mark.asyncio
    async def test_parses_cidr_lines(self):
        # Arrange
        http = FakeHttpClient(text_responses={
            "spamhaus.org": (
                "; Spamhaus DROP\n"
                "1.2.3.0/24 ; SBL1\n"
                "5.6.0.0/16 ; SBL2\n"
            ),
        })
        source = SpamhausDropSource(http)

        # Act
        ips = await source.fetch()

        # Assert
        raws = {ip.raw for ip in ips}
        assert "1.2.3.0/24" in raws
        assert "5.6.0.0/16" in raws
        assert len(ips) == 2

    @pytest.mark.asyncio
    async def test_ignores_comment_lines(self):
        # Arrange
        http = FakeHttpClient(text_responses={
            "spamhaus.org": "; only comments\n; another\n",
        })
        source = SpamhausDropSource(http)

        # Act
        ips = await source.fetch()

        # Assert
        assert len(ips) == 0


class TestFeodoTrackerSource:
    @pytest.mark.asyncio
    async def test_extracts_public_ips(self):
        # Arrange
        http = FakeHttpClient(text_responses={
            "feodotracker": "# Comment\n1.2.3.4\n5.6.7.8\n192.168.1.1\n",
        })
        source = FeodoTrackerSource(http)

        # Act
        ips = await source.fetch()

        # Assert
        raws = {ip.raw for ip in ips}
        assert "1.2.3.4" in raws
        assert "5.6.7.8" in raws
        assert "192.168.1.1" not in raws


class TestBlocklistDeSource:
    @pytest.mark.asyncio
    async def test_extracts_ips(self):
        # Arrange
        http = FakeHttpClient(text_responses={
            "blocklist.de": "8.8.8.8\n1.2.3.4\n",
        })
        source = BlocklistDeSource(http, "ssh")

        # Act
        ips = await source.fetch()

        # Assert
        assert len(ips) == 2
        assert source.name == "Blocklist.de (ssh)"


class TestBinaryDefenseSource:
    @pytest.mark.asyncio
    async def test_skips_comments_and_private(self):
        # Arrange
        http = FakeHttpClient(text_responses={
            "binarydefense": "# comment\n8.8.8.8\n192.168.1.1\n1.2.3.4\n",
        })
        source = BinaryDefenseSource(http)

        # Act
        ips = await source.fetch()

        # Assert
        raws = {ip.raw for ip in ips}
        assert "8.8.8.8" in raws
        assert "1.2.3.4" in raws
        assert "192.168.1.1" not in raws


class TestStamparmIpsumSource:
    @pytest.mark.asyncio
    async def test_filters_by_score(self):
        # Arrange
        http = FakeHttpClient(text_responses={
            "stamparm": "# ipsum\n1.2.3.4\t3\n5.6.7.8\t1\n9.8.7.6\t5\n",
        })
        source = StamparmIpsumSource(http, min_score=2)

        # Act
        ips = await source.fetch()

        # Assert
        raws = {ip.raw for ip in ips}
        assert "1.2.3.4" in raws
        assert "9.8.7.6" in raws
        assert "5.6.7.8" not in raws


class TestTorExitSource:
    @pytest.mark.asyncio
    async def test_extracts_ips(self):
        # Arrange
        http = FakeHttpClient(text_responses={
            "torproject": "185.220.100.240\n185.220.100.241\n",
        })
        source = TorExitSource(http)

        # Act
        ips = await source.fetch()

        # Assert
        assert len(ips) == 2


class TestCinsArmySource:
    @pytest.mark.asyncio
    async def test_extracts_ips(self):
        # Arrange
        http = FakeHttpClient(text_responses={
            "cinsscore": "1.2.3.4\n5.6.7.8\n",
        })
        source = CinsArmySource(http)

        # Act
        ips = await source.fetch()

        # Assert
        assert len(ips) == 2


class TestGreenSnowSource:
    @pytest.mark.asyncio
    async def test_extracts_ips(self):
        # Arrange
        http = FakeHttpClient(text_responses={
            "greensnow": "3.4.5.6\n7.8.9.10\n",
        })
        source = GreenSnowSource(http)

        # Act
        ips = await source.fetch()

        # Assert
        assert len(ips) == 2

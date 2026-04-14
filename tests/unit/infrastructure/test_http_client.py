"""Unit tests for AiohttpClient — retry logic with mocked HTTP."""

import pytest
from aioresponses import aioresponses

from threat_intel.infrastructure.http.aiohttp_client import AiohttpClient


@pytest.fixture
def mock_aiohttp():
    with aioresponses() as m:
        yield m


class TestAiohttpClient:
    @pytest.mark.asyncio
    async def test_successful_get(self, mock_aiohttp):
        # Arrange
        mock_aiohttp.get("http://test.example.com/feed.txt",
                         body="1.2.3.4\n5.6.7.8")
        client = AiohttpClient(max_retries=3)

        # Act
        text = await client.get("http://test.example.com/feed.txt")
        await client.close()

        # Assert
        assert "1.2.3.4" in text
        assert "5.6.7.8" in text

    @pytest.mark.asyncio
    async def test_successful_get_json(self, mock_aiohttp):
        # Arrange
        mock_aiohttp.get("http://test.example.com/api",
                         payload={"data": [1, 2, 3]})
        client = AiohttpClient(max_retries=3)

        # Act
        data = await client.get_json("http://test.example.com/api")
        await client.close()

        # Assert
        assert data["data"] == [1, 2, 3]

    @pytest.mark.asyncio
    async def test_retries_on_500(self, mock_aiohttp):
        # Arrange
        url = "http://test.example.com/down"
        mock_aiohttp.get(url, status=500)
        mock_aiohttp.get(url, status=500)
        mock_aiohttp.get(url, body="ok", status=200)
        client = AiohttpClient(max_retries=3, backoff_base=0.0)

        # Act
        text = await client.get(url)
        await client.close()

        # Assert
        assert text == "ok"

    @pytest.mark.asyncio
    async def test_no_retry_on_404(self, mock_aiohttp):
        # Arrange
        url = "http://test.example.com/gone"
        mock_aiohttp.get(url, status=404)
        client = AiohttpClient(max_retries=3)

        # Act & Assert
        with pytest.raises(Exception):
            await client.get(url)
        await client.close()

    @pytest.mark.asyncio
    async def test_raises_after_all_retries_exhausted(self, mock_aiohttp):
        # Arrange
        url = "http://test.example.com/dead"
        mock_aiohttp.get(url, status=500)
        mock_aiohttp.get(url, status=500)
        mock_aiohttp.get(url, status=500)
        client = AiohttpClient(max_retries=3, backoff_base=0.0)

        # Act & Assert
        with pytest.raises(Exception):
            await client.get(url)
        await client.close()

    @pytest.mark.asyncio
    async def test_session_close(self, mock_aiohttp):
        # Arrange
        mock_aiohttp.get("http://test.example.com/x", body="ok")
        client = AiohttpClient()

        # Act
        await client.get("http://test.example.com/x")
        await client.close()

        # Assert — no error, session cleaned up
        assert client._session is not None
        assert client._session.closed

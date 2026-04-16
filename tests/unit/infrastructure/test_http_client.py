"""Unit tests for RequestsClient — retry logic with mocked HTTP."""

import pytest
from unittest.mock import patch, MagicMock

from threat_intel.infrastructure.http.requests_client import RequestsClient, HttpError


def _mock_response(status=200, text="ok", json_data=None, headers=None):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.url = "http://test.example.com"
    resp.headers = headers or {}
    if json_data is not None:
        resp.json.return_value = json_data
    return resp


class TestRequestsClient:
    def test_successful_get(self):
        client = RequestsClient(max_retries=3)
        with patch.object(client._session, "get",
                          return_value=_mock_response(text="1.2.3.4\n5.6.7.8")):
            text = client.get("http://test.example.com/feed.txt")

        assert "1.2.3.4" in text
        assert "5.6.7.8" in text

    def test_successful_get_json(self):
        client = RequestsClient(max_retries=3)
        with patch.object(client._session, "get",
                          return_value=_mock_response(json_data={"data": [1, 2, 3]})):
            data = client.get_json("http://test.example.com/api")

        assert data["data"] == [1, 2, 3]

    def test_retries_on_500(self):
        client = RequestsClient(max_retries=3, backoff_base=0.01)
        responses = [
            _mock_response(status=500, text="error"),
            _mock_response(status=500, text="error"),
            _mock_response(status=200, text="ok"),
        ]
        with patch.object(client._session, "get", side_effect=responses):
            text = client.get("http://test.example.com/down")

        assert text == "ok"

    def test_no_retry_on_404(self):
        client = RequestsClient(max_retries=3)
        with patch.object(client._session, "get",
                          return_value=_mock_response(status=404, text="not found")):
            with pytest.raises(HttpError) as exc_info:
                client.get("http://test.example.com/gone")
            assert exc_info.value.status == 404

    def test_raises_after_all_retries_exhausted(self):
        client = RequestsClient(max_retries=3, backoff_base=0.01)
        responses = [_mock_response(status=500, text="error")] * 3
        with patch.object(client._session, "get", side_effect=responses):
            with pytest.raises(HttpError):
                client.get("http://test.example.com/dead")

    def test_retries_on_429(self):
        client = RequestsClient(max_retries=3, backoff_base=0.01)
        responses = [
            _mock_response(status=429, text="rate limited"),
            _mock_response(status=200, text="ok"),
        ]
        with patch.object(client._session, "get", side_effect=responses):
            text = client.get("http://test.example.com/ratelimit")

        assert text == "ok"

    def test_close(self):
        client = RequestsClient()
        client.close()
        # No error — session cleaned up

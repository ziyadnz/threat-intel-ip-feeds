"""HTTP client implementation using requests.

Implements the HttpClient port with retry + exponential backoff.
Thread-safe — each thread gets its own connection via requests.Session.
"""

from __future__ import annotations

import logging
import time
from typing import Dict, Optional

import requests

from threat_intel.domain.ports import HttpClient

logger = logging.getLogger(__name__)


class HttpError(Exception):
    """HTTP error with status code."""

    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(f"HTTP {status}: {message}")


class RequestsClient(HttpClient):
    """Sync HttpClient backed by requests.

    Thread-safe: uses a requests.Session for connection pooling.
    """

    def __init__(
        self,
        default_timeout: int = 60,
        max_retries: int = 3,
        backoff_base: float = 2.0,
    ):
        self._default_timeout = default_timeout
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._session = requests.Session()

    def get(self, url: str, headers: Optional[Dict] = None,
            timeout: int = 0) -> str:
        effective_timeout = timeout or self._default_timeout
        return self._request(url, headers, effective_timeout).text

    def get_json(self, url: str, headers: Optional[Dict] = None,
                 timeout: int = 0) -> object:
        effective_timeout = timeout or self._default_timeout
        return self._request(url, headers, effective_timeout).json()

    def close(self) -> None:
        self._session.close()

    def _request(
        self, url: str, headers: Optional[Dict], timeout: int,
    ) -> requests.Response:
        last_error: Optional[Exception] = None

        for attempt in range(self._max_retries):
            try:
                resp = self._session.get(
                    url, headers=headers, timeout=timeout, verify=True,
                )
                if resp.status_code >= 400:
                    self._handle_error(resp, attempt)
                return resp

            except HttpError as e:
                last_error = e
                if 400 <= e.status < 500 and e.status != 429:
                    raise
                self._wait_or_raise(url, attempt, e)

            except requests.RequestException as e:
                last_error = e
                self._wait_or_raise(url, attempt, e)

        raise last_error  # pragma: no cover

    def _handle_error(self, resp: requests.Response, attempt: int):
        status = resp.status_code
        body = resp.text[:200]

        if status == 429:
            retry_after = resp.headers.get("Retry-After")
            wait = (
                float(retry_after)
                if retry_after and retry_after.isdigit()
                else self._backoff_base ** (attempt + 1)
            )
            logger.warning(f"[{resp.url}] Rate limited (429), retrying in {wait}s")
            raise HttpError(429, body)

        if status < 500:
            logger.error(f"[{resp.url}] Client error ({status}), no retry")
            raise HttpError(status, body)

        raise HttpError(status, body)

    def _wait_or_raise(self, url: str, attempt: int, error: Exception):
        if attempt < self._max_retries - 1:
            wait = self._backoff_base ** (attempt + 1)
            logger.warning(
                f"[{url}] Attempt {attempt + 1}/{self._max_retries} "
                f"failed, retrying in {wait}s: {error}"
            )
            time.sleep(wait)
        else:
            logger.error(
                f"[{url}] All {self._max_retries} attempts failed: {error}"
            )
            raise error

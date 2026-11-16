"""HTTP client implementation using requests.

Implements the HttpClient port with retry + exponential backoff.
Thread-safe — each thread gets its own connection via requests.Session.
"""

from __future__ import annotations

import logging
import math
import random
import time
import threading
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Dict, Optional
from urllib.parse import urlsplit

import requests

from threat_intel.domain.ports import HttpClient

logger = logging.getLogger(__name__)


class HttpError(Exception):
    """HTTP error with status code."""

    def __init__(self, status: int, message: str, retry_after: float = 0):
        self.status = status
        self.retry_after = retry_after
        super().__init__(f"HTTP {status}: {message}")


class RetryDeferred(HttpError):
    """Server cooldown exceeds this run's wait budget; use source cache instead."""

    retryable = False

    def __init__(self, status: int, retry_after: float, limit: float):
        super().__init__(status,
                         f"Retry-After {retry_after:g}s exceeds {limit:g}s budget; "
                         "deferring host for this run", retry_after=retry_after)


class RequestsClient(HttpClient):
    """Sync HttpClient backed by requests.

    Thread-safe: uses a requests.Session for connection pooling.
    """

    def __init__(
        self,
        default_timeout: int = 60,
        max_retries: int = 3,
        backoff_base: float = 2.0,
        max_retry_after: float = 30.0,
    ):
        self._default_timeout = default_timeout
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        if not math.isfinite(max_retry_after) or max_retry_after < 0:
            raise ValueError("max_retry_after must be a finite non-negative number")
        self._max_retry_after = max_retry_after
        self._deferred_hosts = {}
        self._deferred_lock = threading.Lock()
        self._local = threading.local()
        self._sessions = []
        self._sessions_lock = threading.Lock()

    @property
    def _session(self):
        if not hasattr(self._local, "session"):
            session = requests.Session()
            self._local.session = session
            with self._sessions_lock:
                self._sessions.append(session)
        return self._local.session

    def get(self, url: str, headers: Optional[Dict] = None,
            timeout: int = 0) -> str:
        effective_timeout = timeout or self._default_timeout
        return self._request(url, headers, effective_timeout).text

    def get_json(self, url: str, headers: Optional[Dict] = None,
                 timeout: int = 0) -> object:
        effective_timeout = timeout or self._default_timeout
        return self._request(url, headers, effective_timeout).json()

    def close(self) -> None:
        for session in self._sessions:
            session.close()
        self._sessions.clear()

    def _request(
        self, url: str, headers: Optional[Dict], timeout: int,
    ) -> requests.Response:
        last_error: Optional[Exception] = None

        for attempt in range(self._max_retries):
            # A cooldown applies to the whole provider, including other OTX pages.
            # Requests already in flight cannot be recalled.
            with self._deferred_lock:
                deferred = self._deferred_hosts.get(urlsplit(url).hostname)
            if deferred is not None:
                raise RetryDeferred(deferred.status, deferred.retry_after, self._max_retry_after)
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

        if status == 429 or status == 503:
            retry_after = resp.headers.get("Retry-After", "")
            wait = 0.0
            if retry_after:
                try:
                    seconds = float(retry_after)
                    wait = max(0.0, seconds) if math.isfinite(seconds) else 0.0
                except ValueError:
                    try:
                        date = parsedate_to_datetime(retry_after)
                        wait = max(0.0, (date - datetime.now(timezone.utc)).total_seconds())
                    except (ValueError, TypeError, OverflowError):
                        pass
            raise HttpError(status, body, retry_after=wait)

        if status < 500:
            logger.error(f"[{resp.url}] Client error ({status}), no retry")
            raise HttpError(status, body)

        raise HttpError(status, body)

    def _wait_or_raise(self, url: str, attempt: int, error: Exception):
        server_wait = getattr(error, "retry_after", 0)
        if server_wait > self._max_retry_after:
            deferred = RetryDeferred(error.status, server_wait, self._max_retry_after)
            with self._deferred_lock:
                self._deferred_hosts[urlsplit(url).hostname] = deferred
            logger.warning("[%s] %s; source cache will be used if available", url, deferred)
            raise deferred from error
        if attempt < self._max_retries - 1:
            if getattr(error, "status", None) == 429 and server_wait == 0:
                # Slower retries for throttling than for transient connection errors.
                wait = (10 if attempt == 0 else 30) + random.uniform(0, 2)
            else:
                wait = max(self._backoff_base ** (attempt + 1), server_wait)
            logger.warning(
                f"[{url}] Attempt {attempt + 1}/{self._max_retries} "
                f"failed, retrying in {wait:.2f}s: {error}"
            )
            time.sleep(wait)
        else:
            logger.error(f"[{url}] All {self._max_retries} attempts failed: {error}")
            raise error

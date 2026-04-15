"""HTTP client implementation using aiohttp.

Implements the async HttpClient port with retry + exponential backoff.
All HTTP knowledge is contained here — the domain never touches aiohttp.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, Optional

import aiohttp

from threat_intel.domain.ports import HttpClient

logger = logging.getLogger(__name__)


class AiohttpClient(HttpClient):
    """Async HttpClient backed by aiohttp.ClientSession.

    Manages its own session lifecycle. Call close() when done,
    or use as an async context manager.
    """

    def __init__(
        self,
        default_timeout: int = 60,
        max_retries: int = 3,
        backoff_base: float = 2.0,
        connector_limit: int = 30,
    ):
        self._default_timeout = default_timeout
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._connector_limit = connector_limit
        self._session: Optional[aiohttp.ClientSession] = None

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(
                limit=self._connector_limit,
            )
            self._session = aiohttp.ClientSession(connector=connector)
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def get(self, url: str, headers: Optional[Dict] = None,
                  timeout: int = 0) -> str:
        effective_timeout = timeout or self._default_timeout
        resp = await self._request(url, headers, effective_timeout)
        return await resp.text()

    async def get_json(self, url: str, headers: Optional[Dict] = None,
                       timeout: int = 0) -> object:
        effective_timeout = timeout or self._default_timeout
        resp = await self._request(url, headers, effective_timeout)
        return await resp.json(content_type=None)

    async def _request(
        self, url: str, headers: Optional[Dict], timeout: int,
    ) -> aiohttp.ClientResponse:
        session = await self._ensure_session()
        last_error: Optional[Exception] = None
        client_timeout = aiohttp.ClientTimeout(total=timeout)

        for attempt in range(self._max_retries):
            try:
                resp = await session.get(
                    url, headers=headers, timeout=client_timeout, ssl=True,
                )
                if resp.status >= 400:
                    body = await resp.text()
                    # 429 Too Many Requests — retry with backoff
                    if resp.status == 429:
                        retry_after = resp.headers.get("Retry-After")
                        wait = (
                            float(retry_after)
                            if retry_after and retry_after.isdigit()
                            else self._backoff_base ** (attempt + 1)
                        )
                        logger.warning(
                            f"[{url}] Rate limited (429), "
                            f"retrying in {wait}s"
                        )
                        raise aiohttp.ClientResponseError(
                            resp.request_info, resp.history,
                            status=resp.status, message=body,
                        )
                    # Other 4xx — permanent, don't retry
                    if 400 <= resp.status < 500:
                        logger.error(
                            f"[{url}] Client error ({resp.status}), no retry"
                        )
                        raise aiohttp.ClientResponseError(
                            resp.request_info, resp.history,
                            status=resp.status, message=body,
                        )
                    raise aiohttp.ClientResponseError(
                        resp.request_info, resp.history,
                        status=resp.status, message=body,
                    )
                return resp

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_error = e

                # 4xx errors are permanent — don't retry (except 429)
                if isinstance(e, aiohttp.ClientResponseError):
                    if 400 <= e.status < 500 and e.status != 429:
                        raise

                if attempt < self._max_retries - 1:
                    wait = self._backoff_base ** (attempt + 1)
                    logger.warning(
                        f"[{url}] Attempt {attempt + 1}/{self._max_retries} "
                        f"failed, retrying in {wait}s: {e}"
                    )
                    await asyncio.sleep(wait)
                else:
                    logger.error(
                        f"[{url}] All {self._max_retries} attempts failed: {e}"
                    )
                    raise

        raise last_error  # pragma: no cover

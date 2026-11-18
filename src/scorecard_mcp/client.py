"""Small async client for the OpenSSF Scorecard REST API (public, no authentication)."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from typing import Any

import httpx

log = logging.getLogger("scorecard_mcp")

DEFAULT_BASE_URL = "https://api.scorecard.dev"
PLATFORMS = ("github.com", "gitlab.com")
RETRY_STATUSES = {429, 502, 503, 504}
CACHE_SECONDS = 600  # the API itself sends max-age=600
_COMMIT = re.compile(r"^[0-9a-fA-F]{40}$")


class ScorecardError(Exception):
    """An API or network failure with a message that is safe to show a model."""


class NotScanned(ScorecardError):
    """The repository has no stored Scorecard result."""


def parse_repo(repo: str) -> tuple[str, str, str]:
    """Return (platform, org, name) from 'github.com/o/r', a full URL, an SSH URL or just 'o/r'."""
    text = repo.strip()
    for prefix in ("https://", "http://", "git@", "ssh://git@", "git://"):
        text = text.removeprefix(prefix)
    text = text.replace(":", "/", 1) if text.startswith(PLATFORMS) and ":" in text.split("/")[0] else text
    text = text.removesuffix(".git").strip("/")
    parts = [p for p in text.split("/") if p]
    if parts and parts[0].lower() in PLATFORMS:
        platform, rest = parts[0].lower(), parts[1:]
    else:
        platform, rest = "github.com", parts
    if len(rest) < 2:
        raise ScorecardError(
            f"Could not read a repository from '{repo}'. Use 'github.com/owner/name' or just 'owner/name' (GitHub is assumed). "
            f"Supported hosts: {', '.join(PLATFORMS)}."
        )
    return platform, rest[0], rest[1]


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


class ScorecardClient:
    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._cache: dict[tuple[str, str | None], tuple[float, dict[str, Any]]] = {}

    @property
    def base_url(self) -> str:
        return os.environ.get("SCORECARD_BASE_URL", DEFAULT_BASE_URL).rstrip("/")

    def clear_cache(self) -> None:
        self._cache.clear()

    def _http(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        if self._client is None or self._client.is_closed or self._loop is not loop:
            self._loop = loop
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(_float_env("SCORECARD_TIMEOUT", 30.0), connect=10.0),
                headers={"Accept": "application/json", "User-Agent": "scorecard-mcp/0.1"},
                follow_redirects=True,
            )
        return self._client

    async def result(self, repo: str, commit: str | None = None) -> dict[str, Any]:
        """Fetch (and briefly cache) the stored Scorecard result for a repository."""
        platform, org, name = parse_repo(repo)
        if commit and not _COMMIT.match(commit):
            raise ScorecardError("commit must be a full 40-character hexadecimal SHA.")
        slug = f"{platform}/{org}/{name}"
        key = (slug.lower(), commit.lower() if commit else None)
        hit = self._cache.get(key)
        ttl = _float_env("SCORECARD_CACHE_SECONDS", CACHE_SECONDS)
        if hit and time.monotonic() - hit[0] < ttl:
            return hit[1]
        data = await self._get(f"/projects/{slug}", {"commit": commit} if commit else None, slug)
        self._cache[key] = (time.monotonic(), data)
        return data

    async def _get(self, path: str, params: dict[str, Any] | None, slug: str) -> dict[str, Any]:
        url = self.base_url + path
        retries = int(_float_env("SCORECARD_RETRIES", 2))
        delay = _float_env("SCORECARD_RETRY_DELAY", 1.0)
        for attempt in range(retries + 1):
            try:
                resp = await self._http().get(url, params=params)
            except httpx.TimeoutException as exc:
                if attempt < retries:
                    await asyncio.sleep(delay * 2**attempt)
                    continue
                raise ScorecardError(f"Request for {slug} timed out ({type(exc).__name__}). The Scorecard API may be slow; retry later.") from exc
            except httpx.HTTPError as exc:
                raise ScorecardError(f"Request for {slug} failed: {type(exc).__name__}: {exc}") from exc
            if resp.status_code in RETRY_STATUSES and attempt < retries:
                wait = delay * 2**attempt
                retry_after = resp.headers.get("retry-after")
                if retry_after and retry_after.isdigit():
                    wait = min(float(retry_after), 10.0)
                await asyncio.sleep(wait)
                continue
            break
        if resp.status_code == 404:
            raise NotScanned(
                f"No Scorecard result stored for {slug}. The public API only has repositories that Scorecard scans "
                "(popular projects and those that publish results from CI). Check the spelling, or run the scorecard CLI locally."
            )
        if resp.status_code == 429:
            raise ScorecardError("Rate limited by the Scorecard API. Wait a moment and retry with fewer repositories at once.")
        if resp.status_code >= 400:
            detail = resp.text[:300].strip()
            raise ScorecardError(f"Scorecard API returned HTTP {resp.status_code} for {slug}. {detail}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise ScorecardError(f"Scorecard API returned a non-JSON response for {slug}.") from exc
        if not isinstance(data, dict):
            raise ScorecardError(f"Unexpected response shape for {slug}.")
        return data

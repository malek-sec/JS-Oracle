"""Fetches JavaScript source files or URLs for analysis."""

import random
from pathlib import Path

import httpx

from utils.logger import logger


class JSFetcher:

    def __init__(self):
        self.timeout = 15
        self._user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
        ]

    def _get_random_headers(self) -> dict:
        return {
            "User-Agent": random.choice(self._user_agents),
            "Accept-Language": "en-US,en;q=0.9",
        }

    def fetch_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"Invalid URL scheme: {url!r} — must start with http:// or https://")

        try:
            response = httpx.get(url, headers=self._get_random_headers(), timeout=self.timeout, follow_redirects=True)
        except httpx.TimeoutException:
            raise ValueError(f"Request timed out for {url}")
        except httpx.SSLError:
            raise ValueError(f"SSL error for {url}")
        except httpx.RequestError as e:
            raise ValueError(f"Network error: {e}")

        if not response.is_success:
            raise ValueError(f"HTTP {response.status_code} for {url}")

        return response.text

    def fetch_file(self, path: str) -> str:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"File not found: {path!r}")
        return p.read_text(encoding="utf-8")

    def fetch_directory(self, dir_path: str) -> dict[str, str]:
        d = Path(dir_path)
        if not d.is_dir():
            raise NotADirectoryError(f"Not a directory: {dir_path!r}")

        js_files = list(d.rglob("*.js"))
        logger.info(f"Found {len(js_files)} JS file(s) in {dir_path!r}")

        results: dict[str, str] = {}
        for js_file in js_files:
            try:
                results[str(js_file.relative_to(d))] = self.fetch_file(str(js_file))
            except Exception as e:
                logger.warning(f"Skipping {js_file.name}: {e}")

        return results

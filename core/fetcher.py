"""Fetches JavaScript source files or URLs for analysis."""

import random
from pathlib import Path

import httpx

from utils.logger import logger


# Hard cap on a single JS source (bytes). Guards against OOM from a hostile or
# runaway URL/file and against burning API budget on a giant blob. ~15 MB of JS
# is already far larger than any real bundle.
_DEFAULT_MAX_BYTES = 15 * 1024 * 1024


class JSFetcher:

    def __init__(
        self,
        max_bytes: int = _DEFAULT_MAX_BYTES,
        proxy: str | None = None,
        extra_headers: dict | None = None,
        verify: bool = True,
    ):
        self.timeout = 15
        self.max_bytes = max_bytes
        self.proxy = proxy            # e.g. http://127.0.0.1:8080 to route through Burp
        self.verify = verify          # set False to accept self-signed TLS certs
        self.extra_headers = dict(extra_headers or {})  # auth / cookies for gated JS
        self._user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
        ]

    def _get_random_headers(self) -> dict:
        headers = {
            "User-Agent": random.choice(self._user_agents),
            "Accept-Language": "en-US,en;q=0.9",
        }
        # User-supplied headers win (e.g. an explicit User-Agent, Authorization).
        headers.update(self.extra_headers)
        return headers

    def fetch_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"Invalid URL scheme: {url!r} — must start with http:// or https://")

        try:
            with httpx.Client(
                proxy=self.proxy,
                verify=self.verify,
                timeout=self.timeout,
                follow_redirects=True,
            ) as client, client.stream(
                "GET", url, headers=self._get_random_headers()
            ) as response:
                if not response.is_success:
                    raise ValueError(f"HTTP {response.status_code} for {url}")

                # Reject up front if the server declares an oversized body.
                declared = response.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > self.max_bytes:
                    raise ValueError(
                        f"Response too large ({int(declared):,} bytes > "
                        f"{self.max_bytes:,} byte cap) for {url}"
                    )

                # Enforce the cap while streaming, in case Content-Length lies
                # or is absent (chunked transfer).
                buf = bytearray()
                for chunk in response.iter_bytes():
                    buf.extend(chunk)
                    if len(buf) > self.max_bytes:
                        raise ValueError(
                            f"Response exceeded {self.max_bytes:,} byte cap for {url}"
                        )
                encoding = response.encoding or "utf-8"
        except httpx.TimeoutException:
            raise ValueError(f"Request timed out for {url}")
        except httpx.SSLError:
            raise ValueError(f"SSL error for {url}")
        except httpx.RequestError as e:
            raise ValueError(f"Network error: {e}")

        return bytes(buf).decode(encoding, errors="replace")

    def fetch_file(self, path: str) -> str:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"File not found: {path!r}")
        if not p.is_file():
            raise ValueError(f"Not a regular file: {path!r}")
        size = p.stat().st_size
        if size > self.max_bytes:
            raise ValueError(
                f"File too large ({size:,} bytes > {self.max_bytes:,} byte cap): {path!r}"
            )
        # errors="replace" so a stray non-UTF-8 byte can't crash the whole run.
        return p.read_text(encoding="utf-8", errors="replace")

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

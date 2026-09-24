"""Headless-browser rendering for JavaScript-heavy targets.

Regex crawling only sees the JS referenced in a page's *initial* HTML. Modern
single-page apps (React, Vue, Angular, Next.js, ...) inject most of their code at
runtime — webpack chunks, lazy-loaded modules, dynamic imports — so a plain HTTP
fetch returns almost no ``.js``. That is the classic "the tool found nothing, so
I ran another one" problem.

This module drives a real (headless) Chromium via Playwright: it loads the page,
lets the app boot, and captures both the post-render DOM (for ``<script src>``
extraction) and every JavaScript response the browser actually requested over the
network (webpack chunks and dynamic imports included).

Playwright is an OPTIONAL dependency — only needed for ``--render``:

    pip install playwright          # the browser itself ships with the env,
                                    # or run:  playwright install chromium

The sync API is single-threaded, so a renderer instance must be used from one
thread (the crawler drives page fetches serially when rendering; downloading and
analyzing the discovered JS still runs fully concurrent).
"""

import glob
import os

from utils.logger import logger

try:  # Optional dependency — import lazily so non-render runs never need it.
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover - exercised only without the extra installed
    sync_playwright = None


def playwright_available() -> bool:
    return sync_playwright is not None


def _find_chromium() -> str | None:
    """Locate a pre-installed Chromium when Playwright's default path misses it.

    Some environments ship a Chromium build whose version doesn't match the
    installed Playwright package, so the default launch fails. We fall back to
    whatever ``chrome``/``headless_shell`` binary exists under the browsers path.
    """
    roots = [os.environ.get("PLAYWRIGHT_BROWSERS_PATH", ""), os.path.expanduser("~/.cache/ms-playwright")]
    patterns = ["chromium-*/chrome-linux/chrome", "chromium-*/chrome-mac/*.app/Contents/MacOS/*",
                "chromium-*/chrome-win/chrome.exe", "chromium_headless_shell-*/chrome-linux/headless_shell"]
    for root in roots:
        if not root:
            continue
        for pat in patterns:
            hits = sorted(glob.glob(os.path.join(root, pat)))
            if hits:
                return hits[-1]  # newest build
    return None


class BrowserRenderer:
    """Render pages in headless Chromium and capture the JS they load.

    Use as a context manager so the browser is always cleaned up::

        with BrowserRenderer() as r:
            final_url, ctype, html = r.fetch_page("https://app.example.com")
            extra_js = r.captured_js   # network-loaded .js (chunks, imports)
    """

    def __init__(self, proxy=None, verify=True, extra_headers=None, timeout=20, wait_ms=2000):
        if not playwright_available():
            raise RuntimeError(
                "The --render option needs Playwright. Install it with:\n"
                "  pip install playwright        (then, if needed:  playwright install chromium)"
            )
        self.proxy = proxy
        self.verify = verify
        self.extra_headers = dict(extra_headers or {})
        self.timeout_ms = timeout * 1000
        self.wait_ms = wait_ms
        self.captured_js: set[str] = set()
        self._pw = None
        self._browser = None
        self._context = None

    def __enter__(self):
        self._pw = sync_playwright().start()
        launch_kwargs = {"headless": True, "args": ["--no-sandbox", "--disable-dev-shm-usage"]}
        if self.proxy:
            launch_kwargs["proxy"] = {"server": self.proxy}
        try:
            self._browser = self._pw.chromium.launch(**launch_kwargs)
        except Exception as e:
            exe = _find_chromium()
            if not exe:
                self._pw.stop()
                raise RuntimeError(
                    f"Could not launch Chromium ({e}). Run 'playwright install chromium'."
                ) from e
            logger.info(f"Using detected Chromium at {exe}")
            self._browser = self._pw.chromium.launch(executable_path=exe, **launch_kwargs)

        self._context = self._browser.new_context(
            ignore_https_errors=not self.verify,
            extra_http_headers=self.extra_headers or None,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            ),
        )
        # Record every JavaScript response the browser fetches — this is what
        # catches dynamically loaded chunks that never appear in the source HTML.
        self._context.on("response", self._on_response)
        return self

    def __exit__(self, *exc):
        for closer in (self._context, self._browser):
            try:
                if closer:
                    closer.close()
            except Exception:
                pass
        try:
            if self._pw:
                self._pw.stop()
        except Exception:
            pass

    def _on_response(self, response):
        try:
            url = response.url
            ctype = (response.headers or {}).get("content-type", "").lower()
            path = url.split("?", 1)[0].split("#", 1)[0]
            if url.startswith(("http://", "https://")) and (
                path.lower().endswith(".js") or "javascript" in ctype
            ):
                self.captured_js.add(url)
        except Exception:
            pass  # never let a bad response event break a crawl

    def fetch_page(self, url: str) -> tuple[str, str, str]:
        """Render ``url`` and return ``(final_url, "text/html", rendered_html)``.

        Signature matches :meth:`JSFetcher.fetch_page` so the crawler can use a
        renderer as a drop-in page fetcher. Never raises: a page that fails to
        load returns empty text and is skipped by the crawler.
        """
        if not url.startswith(("http://", "https://")):
            return (url, "", "")
        page = None
        try:
            page = self._context.new_page()
            page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")
            # Give client-side routers / lazy chunks a moment to fire their loads.
            try:
                page.wait_for_load_state("networkidle", timeout=self.wait_ms)
            except Exception:
                pass
            page.wait_for_timeout(min(self.wait_ms, 2000))
            html = page.content()
            final_url = page.url
            return (final_url, "text/html", html)
        except Exception as e:
            logger.warning(f"Render failed for {url}: {e}")
            return (url, "", "")
        finally:
            if page:
                try:
                    page.close()
                except Exception:
                    pass

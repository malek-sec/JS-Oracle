"""Discovery engine: turn a target domain or URL list into JS sources.

This is what makes js-oracle standalone — no more running getJS/katana/hakrawler
first. Give it a domain (``-d example.com``) or a file of URLs (``-l urls.txt``)
and it will:

  * fetch the seed pages,
  * follow same-scope links up to a bounded depth (breadth-first, concurrent),
  * extract every referenced ``.js`` file (``<script src>`` + generic ``.js``
    references embedded in HTML/JS),
  * capture inline ``<script>`` bodies (secrets hide there too),
  * optionally pull historic ``.js`` URLs from the Wayback Machine,
  * and collect query-string parameter names seen along the way.

Everything is best-effort: a dead link, a timeout, or a garbage page is logged
and skipped, never fatal. The heavy analysis then runs over whatever was found.
"""

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from utils.logger import logger

# ── extraction patterns ──────────────────────────────────────────────────────
# <script ... src="..."> (quoted; the overwhelmingly common form).
_SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']""", re.IGNORECASE)

# Inline <script> bodies (any <script> WITHOUT a src attribute).
_INLINE_SCRIPT_RE = re.compile(
    r"""<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>""",
    re.IGNORECASE | re.DOTALL,
)

# Any quoted/parenthesised reference ending in .js (optionally with a query).
# Requiring a delimiter right after the extension keeps '.json'/'.jsx' out.
_JS_REF_RE = re.compile(
    r"""["'(]\s*([^"'()\s<>]+?\.js(?:\?[^"'()\s<>]*)?)\s*["')]""",
    re.IGNORECASE,
)

# <a href="..."> for crawling (drops in-page #fragments).
_HREF_RE = re.compile(r"""<a\b[^>]*?\bhref\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)

# Query-string parameter names, e.g. ?id=1&redirect=... -> {id, redirect}.
_PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_\-]{0,63})=")


@dataclass
class DiscoveryResult:
    """What a crawl found."""

    js_urls: list[str] = field(default_factory=list)          # absolute .js URLs, de-duped
    inline_scripts: dict[str, str] = field(default_factory=dict)  # label -> inline JS body
    parameters: set[str] = field(default_factory=set)         # query param names seen
    pages_crawled: int = 0

    @property
    def source_count(self) -> int:
        return len(self.js_urls) + len(self.inline_scripts)


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _in_scope(url: str, scope_hosts: set[str], include_subdomains: bool) -> bool:
    """Is ``url`` within the target scope?

    In-scope means the host equals a scope host, or (when subdomains are allowed)
    is a subdomain of one — so ``api.example.com`` counts for ``example.com``.
    """
    host = _host(url)
    if not host:
        return False
    for scope in scope_hosts:
        if host == scope:
            return True
        if include_subdomains and host.endswith("." + scope):
            return True
    return False


def _looks_like_js(url: str) -> bool:
    """True if the URL's path ends in .js (ignoring any query string)."""
    path = urlsplit(url).path
    return path.lower().endswith(".js")


class JSCrawler:
    def __init__(
        self,
        fetcher,
        max_depth: int = 2,
        max_pages: int = 200,
        include_subdomains: bool = True,
        concurrency: int = 10,
    ):
        self.fetcher = fetcher
        self.max_depth = max(0, max_depth)
        self.max_pages = max(1, max_pages)
        self.include_subdomains = include_subdomains
        self.concurrency = max(1, concurrency)

    # ── reference extraction ────────────────────────────────────────────────
    def _collect_js_refs(self, base_url: str, text: str) -> set[str]:
        """Absolute .js URLs referenced anywhere in ``text``."""
        refs: set[str] = set()
        for m in _SCRIPT_SRC_RE.finditer(text):
            refs.add(urljoin(base_url, m.group(1).strip()))
        for m in _JS_REF_RE.finditer(text):
            candidate = m.group(1).strip()
            # Skip protocol-relative/data noise handled by urljoin anyway.
            refs.add(urljoin(base_url, candidate))
        # Keep only real http(s) .js URLs.
        return {r for r in refs if r.startswith(("http://", "https://")) and _looks_like_js(r)}

    def _collect_links(self, base_url: str, text: str) -> set[str]:
        links: set[str] = set()
        for m in _HREF_RE.finditer(text):
            joined = urljoin(base_url, m.group(1).strip())
            if joined.startswith(("http://", "https://")):
                links.add(joined.split("#", 1)[0])
        return links

    def _collect_inline(self, page_url: str, text: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for idx, m in enumerate(_INLINE_SCRIPT_RE.finditer(text), start=1):
            body = m.group(1).strip()
            # Ignore trivial/JSON-LD/config stubs; keep anything with real code.
            if len(body) >= 40:
                out[f"{page_url} (inline #{idx})"] = body
        return out

    @staticmethod
    def _collect_params(url: str) -> set[str]:
        return {m.group(1) for m in _PARAM_RE.finditer(url)}

    # ── crawl ───────────────────────────────────────────────────────────────
    def discover(
        self,
        seeds: list[str],
        scope_hosts: set[str],
        crawl: bool = True,
    ) -> DiscoveryResult:
        """Breadth-first discovery starting from ``seeds``.

        ``scope_hosts`` bounds link-following. ``crawl=False`` fetches only the
        seeds themselves (depth 0) — useful when a URL list already points at the
        interesting pages.
        """
        result = DiscoveryResult()
        js_seen: set[str] = set()
        visited: set[str] = set()

        # Seeds that are already .js URLs need no page fetch — analyze them directly.
        frontier: list[str] = []
        for s in seeds:
            result.parameters |= self._collect_params(s)
            if _looks_like_js(s):
                if s not in js_seen:
                    js_seen.add(s)
                    result.js_urls.append(s)
            else:
                frontier.append(s)

        max_depth = self.max_depth if crawl else 0
        depth = 0
        while frontier and depth <= max_depth:
            # De-dupe the frontier and honour the global page budget.
            batch = []
            for url in frontier:
                if len(visited) >= self.max_pages:
                    break
                if url in visited or not _in_scope(url, scope_hosts, self.include_subdomains):
                    continue
                visited.add(url)
                batch.append(url)
            if not batch:
                break

            logger.info(f"Crawl depth {depth}: fetching {len(batch)} page(s)...")
            next_frontier: set[str] = set()
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                for page_url, content_type, text in pool.map(self.fetcher.fetch_page, batch):
                    if not text:
                        continue
                    result.pages_crawled += 1
                    result.parameters |= self._collect_params(page_url)

                    # Extract .js references from every fetched body.
                    for js in self._collect_js_refs(page_url, text):
                        if js not in js_seen:
                            js_seen.add(js)
                            result.js_urls.append(js)
                            result.parameters |= self._collect_params(js)

                    # Only parse HTML pages for inline scripts and further links.
                    if "html" in content_type or (not content_type and "<html" in text.lower()):
                        result.inline_scripts.update(self._collect_inline(page_url, text))
                        if depth < max_depth:
                            for link in self._collect_links(page_url, text):
                                if _in_scope(link, scope_hosts, self.include_subdomains):
                                    next_frontier.add(link)
                                    result.parameters |= self._collect_params(link)

            frontier = [u for u in next_frontier if u not in visited]
            depth += 1

        return result

    # ── wayback machine (opt-in) ────────────────────────────────────────────
    def wayback_js(self, domain: str, limit: int = 5000) -> list[str]:
        """Historic .js URLs for ``domain`` from the Wayback Machine CDX API.

        Best-effort: any network/parse failure returns an empty list. Great for
        surfacing old bundles that still resolve but are no longer linked.
        """
        cdx = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*&output=text&fl=original&collapse=urlkey&limit={limit}"
        )
        _, _, text = self.fetcher.fetch_page(cdx)
        if not text:
            return []
        out: list[str] = []
        seen: set[str] = set()
        for line in text.splitlines():
            url = line.strip()
            if url and _looks_like_js(url) and url not in seen:
                seen.add(url)
                out.append(url)
        logger.info(f"Wayback: {len(out)} historic .js URL(s) for {domain}.")
        return out


def build_seeds(domain: str | None, urls: list[str]) -> tuple[list[str], set[str]]:
    """Normalise CLI inputs into ``(seed_urls, scope_hosts)``.

    A bare ``-d example.com`` becomes ``https://example.com`` with scope host
    ``example.com``. Each ``-l`` URL contributes its own host to the scope.
    """
    seeds: list[str] = []
    scope: set[str] = set()

    if domain:
        d = domain.strip()
        if not d.startswith(("http://", "https://")):
            d = "https://" + d
        seeds.append(d)
        host = _host(d)
        if host:
            scope.add(host)

    for u in urls:
        u = u.strip()
        if not u:
            continue
        if not u.startswith(("http://", "https://")):
            u = "https://" + u
        seeds.append(u)
        host = _host(u)
        if host:
            scope.add(host)

    # De-dupe seeds, preserve order.
    seeds = list(dict.fromkeys(seeds))
    return seeds, scope

"""Tests for the discovery crawler (JS extraction, scope, seed building)."""

from core.crawler import JSCrawler, DiscoveryResult, build_seeds


class _FakeFetcher:
    """Serves canned (final_url, content_type, text) responses per URL."""

    def __init__(self, pages: dict):
        self.pages = pages
        self.requested: list[str] = []

    def fetch_page(self, url: str):
        self.requested.append(url)
        return self.pages.get(url, (url, "", ""))


def test_build_seeds_bare_domain():
    seeds, scope = build_seeds("example.com", [])
    assert seeds == ["https://example.com"]
    assert scope == {"example.com"}


def test_build_seeds_merges_list_hosts():
    seeds, scope = build_seeds("example.com", ["https://api.example.com/app.js", "sub.other.com/x"])
    assert "https://example.com" in seeds
    assert "https://api.example.com/app.js" in seeds
    assert scope == {"example.com", "api.example.com", "sub.other.com"}


def test_collect_js_refs_finds_script_src_and_bare_refs():
    fetcher = _FakeFetcher({})
    crawler = JSCrawler(fetcher)
    html = (
        '<script src="/static/app.js"></script>'
        '<script src="https://cdn.example.com/vendor.js?v=2"></script>'
        'fetch("/api/data.js");'
        'var cfg = "/settings.json";'  # must NOT match (.json)
    )
    refs = crawler._collect_js_refs("https://example.com/", html)
    assert "https://example.com/static/app.js" in refs
    assert "https://cdn.example.com/vendor.js?v=2" in refs
    assert "https://example.com/api/data.js" in refs
    assert all(".json" not in r for r in refs)


def test_collect_inline_skips_tiny_bodies():
    crawler = JSCrawler(_FakeFetcher({}))
    html = "<script>var a=1;</script><script>" + "x=" * 40 + "</script>"
    inline = crawler._collect_inline("https://example.com/", html)
    assert len(inline) == 1  # the tiny one is dropped


def test_discover_follows_links_within_scope_only():
    pages = {
        "https://example.com": (
            "https://example.com",
            "text/html",
            '<a href="/about">a</a><a href="https://evil.com/x">b</a>'
            '<script src="/main.js"></script>',
        ),
        "https://example.com/about": (
            "https://example.com/about",
            "text/html",
            '<script src="/about.js"></script>',
        ),
    }
    fetcher = _FakeFetcher(pages)
    crawler = JSCrawler(fetcher, max_depth=1, concurrency=1)
    result = crawler.discover(["https://example.com"], {"example.com"})

    assert "https://example.com/main.js" in result.js_urls
    assert "https://example.com/about.js" in result.js_urls
    # Out-of-scope link must never be fetched.
    assert "https://evil.com/x" not in fetcher.requested


def test_discover_js_seed_needs_no_fetch():
    fetcher = _FakeFetcher({})
    crawler = JSCrawler(fetcher)
    result = crawler.discover(["https://example.com/app.js?id=1"], {"example.com"})
    assert result.js_urls == ["https://example.com/app.js?id=1"]
    assert "id" in result.parameters
    assert fetcher.requested == []  # a .js seed is analyzed directly


def test_discover_respects_max_pages():
    pages = {
        "https://example.com": (
            "https://example.com",
            "text/html",
            '<a href="/p1">1</a><a href="/p2">2</a><a href="/p3">3</a>',
        )
    }
    fetcher = _FakeFetcher(pages)
    crawler = JSCrawler(fetcher, max_depth=5, max_pages=1, concurrency=1)
    crawler.discover(["https://example.com"], {"example.com"})
    assert len(fetcher.requested) == 1  # budget of 1 page honoured


def test_source_count_counts_js_and_inline():
    r = DiscoveryResult(js_urls=["a.js", "b.js"], inline_scripts={"p#1": "code"})
    assert r.source_count == 3

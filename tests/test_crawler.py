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


def test_collect_js_refs_ignores_template_literals_and_analytics():
    crawler = JSCrawler(_FakeFetcher({}))
    html = (
        '<script src="https://www.googletagmanager.com/gtm.js?id=GTM-XXaa"></script>'
        '<script src="/js/gtm.js"></script>'                      # bare GTM loader
        'var u = "https://cdn.example.com/app.js?id=${gtmId}";'   # template literal
        '<script src="/js/real.js"></script>'
    )
    refs = crawler._collect_js_refs("https://example.com/", html)
    # Only the genuine app script survives.
    assert refs == {"https://example.com/js/real.js"}
    assert all("gtm.js" not in r for r in refs)
    assert all("${" not in r for r in refs)


def test_discover_skips_out_of_scope_redirect_target():
    # An in-scope link whose fetch redirects out of scope must not be harvested.
    pages = {
        "https://example.com": (
            "https://example.com",
            "text/html",
            '<a href="/edit">edit</a>',
        ),
        # The crawler requests the in-scope /edit URL, but the fetcher reports a
        # final URL on github.com (a redirect) with its own inline script.
        "https://example.com/edit": (
            "https://github.com/login",
            "text/html",
            "<script>var leaked = 1234567890;" + "x" * 60 + "</script>",
        ),
    }
    fetcher = _FakeFetcher(pages)
    crawler = JSCrawler(fetcher, max_depth=1, concurrency=1)
    result = crawler.discover(["https://example.com"], {"example.com"})
    # The out-of-scope redirect page contributed nothing.
    assert all("github.com" not in label for label in result.inline_scripts)
    assert result.pages_crawled == 1  # only the in-scope seed counted


def test_collect_js_refs_decodes_html_entities():
    crawler = JSCrawler(_FakeFetcher({}))
    html = '<script src="https://cdn.example.com/main.js?a=1&amp;b=2"></script>'
    refs = crawler._collect_js_refs("https://example.com/", html)
    assert "https://cdn.example.com/main.js?a=1&b=2" in refs
    assert all("&amp;" not in r for r in refs)


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


def test_custom_page_fetch_is_used():
    # A renderer stands in via page_fetch; the crawler must call it, not the
    # default HTTP fetcher.
    calls: list[str] = []

    def render_fetch(url):
        calls.append(url)
        return (url, "text/html", '<script src="/spa.js"></script>')

    crawler = JSCrawler(_FakeFetcher({}), max_depth=0, page_fetch=render_fetch, page_workers=1)
    result = crawler.discover(["https://example.com"], {"example.com"})
    assert calls == ["https://example.com"]
    assert "https://example.com/spa.js" in result.js_urls


def test_site_seeds_parses_robots_and_sitemap():
    pages = {
        "https://example.com/robots.txt": (
            "https://example.com/robots.txt",
            "text/plain",
            "User-agent: *\nDisallow: /admin/panel\nSitemap: https://example.com/sitemap.xml\n",
        ),
        "https://example.com/sitemap.xml": (
            "https://example.com/sitemap.xml",
            "application/xml",
            "<urlset><url><loc>https://example.com/dashboard</loc></url>"
            "<url><loc>https://evil.com/x</loc></url></urlset>",
        ),
    }
    crawler = JSCrawler(_FakeFetcher(pages))
    seeds = crawler.site_seeds("https://example.com/", {"example.com"})
    assert "https://example.com/admin/panel" in seeds   # from robots Disallow
    assert "https://example.com/dashboard" in seeds      # from sitemap <loc>
    assert "https://evil.com/x" not in seeds             # out of scope, dropped


def test_site_seeds_follows_nested_sitemap_index():
    pages = {
        "https://example.com/robots.txt": ("https://example.com/robots.txt", "text/plain", ""),
        "https://example.com/sitemap.xml": (
            "https://example.com/sitemap.xml",
            "application/xml",
            "<sitemapindex><sitemap><loc>https://example.com/sub.xml</loc></sitemap></sitemapindex>",
        ),
        "https://example.com/sub.xml": (
            "https://example.com/sub.xml",
            "application/xml",
            "<urlset><url><loc>https://example.com/deep/page</loc></url></urlset>",
        ),
    }
    crawler = JSCrawler(_FakeFetcher(pages))
    seeds = crawler.site_seeds("https://example.com/", {"example.com"})
    assert "https://example.com/deep/page" in seeds

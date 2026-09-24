"""js-oracle: CLI entry point."""

# load_dotenv() must run before importing core.analyzer so the provider client
# (anthropic.Anthropic() / genai.Client()) can find its API key when a
# JSAnalyzer is later constructed.
from dotenv import load_dotenv
load_dotenv()

import functools
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.fetcher import JSFetcher
from core.crawler import JSCrawler, build_seeds, _looks_like_js
from core.renderer import BrowserRenderer, playwright_available
from core.preprocessor import preprocessor
from core.analyzer import JSAnalyzer
from core.merger import result_merger, _SEVERITY_RANK
from core.patterns import is_known_library, offline_findings
from core.cache import analysis_cache
from output.reporter import ReportGenerator
from utils.logger import get_logger

# Keep in sync with pyproject.toml [project].version.
APP_VERSION = "0.1.0"

BANNER = r"""
    _____  ___    ___  ____    ____  ____  ____  ____     ___
   (_  _) / __)  / __)(  _ \  / ___)(  _ \/ ___)(  _ \   / __)
     )(   \__ \ ( (__  )   /  \___ \ )___/\___ \ )   /  ( (__
    (__)  (___/  \___)(__)__)  (____/(__)  (____/(__)__)  \___)
"""

# Module-level console used only for the banner (before per-command consoles exist).
_banner_console = Console()

_SEVERITY_STYLES = {
    "critical": "red bold",
    "high": "bright_red",
    "medium": "yellow",
    "low": "cyan",
    "info": "white",
    "none": "green",
}


def print_banner():
    _banner_console.print(
        Panel(
            f"[bold yellow]{BANNER}[/bold yellow]\n"
            "[cyan]AI-powered JavaScript analysis tool for bug bounty hunters[/cyan]",
            border_style="bright_yellow",
            expand=False,
        )
    )


def _parse_headers(raw_headers) -> dict:
    """Parse ``('Name: Value', ...)`` CLI headers into a dict."""
    result: dict[str, str] = {}
    for h in raw_headers:
        if ":" not in h:
            raise ValueError(f"Invalid header {h!r}. Expected 'Name: Value'.")
        name, _, value = h.partition(":")
        name = name.strip()
        if not name:
            raise ValueError(f"Invalid header {h!r}. Empty header name.")
        result[name] = value.strip()
    return result


def _read_url_list(path: str) -> list[str]:
    """Read URLs (one per line) from a file, or from stdin when path is '-'.

    Blank lines and lines starting with '#' are ignored.
    """
    if path == "-":
        lines = sys.stdin.read().splitlines()
    else:
        p = Path(path)
        if not p.is_file():
            raise click.UsageError(f"URL list not found: {path!r}")
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def _provider_key_present() -> bool:
    """True if an API key for the configured AI_PROVIDER looks available.

    Lets ``hunt`` fall back to a free offline-only scan (instead of erroring)
    when the user has no key configured — keeping the tool useful out of the box.
    """
    import os

    provider = os.environ.get("AI_PROVIDER", "anthropic").strip().lower()
    if provider == "gemini":
        return bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def run_pipeline(
    source_name: str,
    content: str,
    target_domain: str,
    reporter: ReportGenerator,
    console: Console,
    use_cache: bool,
    logger,
    model: str | None = None,
    chunk_delay: int = 5,
    dry_run: bool = False,
    regex_endpoints: bool = False,
    offline_only: bool = False,
) -> dict | None:
    """Run the full analysis pipeline for a single JS source.

    Returns the merged results dict, or None if the pipeline produced nothing.
    When ``offline_only`` is set, the AI call is skipped entirely (no API key,
    no cost) — only the deterministic offline scan runs.
    """
    logger.info(f"Analyzing: {source_name}")

    chunk_results = []
    if not offline_only:
        js_analyzer = JSAnalyzer(model=model)

        chunks = preprocessor.prepare(content)
        logger.info(f"Preprocessing produced {len(chunks)} chunk(s) for '{source_name}'.")

        for idx, chunk in enumerate(chunks, start=1):
            try:
                result = js_analyzer.analyze(chunk, target_domain, use_cache, dry_run=dry_run)
                chunk_results.append(result)
            except Exception as e:
                logger.error(f"Chunk {idx}/{len(chunks)} failed for '{source_name}': {e}")

            # Sleep between chunks to respect rate limits (skip after the last chunk).
            if idx < len(chunks):
                logger.debug(f"Waiting {chunk_delay}s between chunks (rate limit cooldown)...")
                time.sleep(chunk_delay)

    # Offline, no-API pre-scan (source maps, secrets, optional endpoints). Merged
    # alongside the chunks so it is still reported even if every API call failed.
    offline = offline_findings(content, include_endpoints=regex_endpoints)
    offline_count = (
        len(offline["secrets"]) + len(offline["endpoints"]) + len(offline["suspicious_logic"])
    )
    if offline_count:
        chunk_results.append(offline)
        logger.info(
            f"Offline scan surfaced {offline_count} deterministic finding(s) for '{source_name}'."
        )

    if not chunk_results:
        # Empty means a clean file (no findings) — per-chunk failures, if any,
        # are already logged as errors above, so this is not itself a failure.
        logger.info(f"No findings for '{source_name}'.")
        return None

    merged = result_merger.merge(chunk_results)

    if target_domain:
        merged = result_merger.filter_third_party(merged, target_domain)

    paths = reporter.render(merged, source_name)
    logger.info(f"Reports saved to: {paths['markdown_path']}")
    return merged


def _print_batch_summary(console: Console, results: list[tuple[str, dict]]) -> None:
    """Print an aggregate summary across every analyzed source."""
    totals = {"endpoints": 0, "secrets": 0, "auth_logic": 0, "suspicious_logic": 0}
    rows = []
    for name, merged in results:
        for k in totals:
            totals[k] += len(merged.get(k, []))
        summ = merged.get("analysis_summary", {})
        rows.append((name, summ.get("highest_severity", "none"), summ.get("total_findings", 0)))
    rows.sort(key=lambda r: (_SEVERITY_RANK.get(r[1], 0), r[2]), reverse=True)

    console.print()
    console.print(
        Panel(
            f"Sources analyzed: [bold]{len(results)}[/bold]    "
            f"Endpoints: [bold]{totals['endpoints']}[/bold]    "
            f"Secrets: [bold red]{totals['secrets']}[/bold red]    "
            f"Auth: [bold]{totals['auth_logic']}[/bold]    "
            f"Suspicious: [bold]{totals['suspicious_logic']}[/bold]",
            title="[bold cyan]Batch Summary[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )

    tbl = Table(title="Sources by severity", box=box.ROUNDED)
    tbl.add_column("Severity", no_wrap=True)
    tbl.add_column("Findings", justify="right", no_wrap=True)
    tbl.add_column("Source")
    for name, sev, total in rows[:20]:
        style = _SEVERITY_STYLES.get(sev, "white")
        tbl.add_row(f"[{style}]{sev.upper()}[/{style}]", str(total), name)
    console.print(tbl)


@click.group()
@click.version_option(version=APP_VERSION, prog_name="js-oracle")
def cli():
    """AI-powered JavaScript analysis tool for bug bounty hunters."""
    print_banner()


@cli.command()
@click.option("--url", "-u", multiple=True, help="JS file URL to analyze (repeatable).")
@click.option("--url-list", "url_list", default=None, help="File of JS URLs, one per line ('-' reads stdin).")
@click.option("--file", "-f", "file_path", default=None, help="Local JS file path.")
@click.option("--dir", "-d", "dir_path", default=None, help="Directory of JS files (recursive).")
@click.option("--domain", default=None, help="Target domain for filtering third-party endpoints.")
@click.option("--output", "-o", default="./reports", show_default=True, help="Output directory for reports.")
@click.option("--html", "html_out", is_flag=True, default=False, help="Also write a styled HTML report per source, plus a batch index.html.")
@click.option("--regex-endpoints", is_flag=True, default=False, help="Add an offline LinkFinder-style endpoint/URL sweep (noisier, deterministic).")
@click.option("--offline", "offline_only", is_flag=True, default=False, help="Deterministic scan only — no AI call, no API key, no cost. Great for a free first-pass triage.")
@click.option("--skip-libs", is_flag=True, default=False, help="Skip well-known JS libraries (jquery, bootstrap, gsap, ...) — don't waste AI spend on vendor code.")
@click.option("--concurrency", "-c", default=1, type=int, show_default=True, help="Analyze this many sources in parallel (best with URL lists / --dir).")
@click.option("--proxy", default=None, help="Route URL fetches through a proxy, e.g. http://127.0.0.1:8080 (Burp).")
@click.option("--insecure", is_flag=True, default=False, help="Skip TLS certificate verification when fetching URLs.")
@click.option("--header", "-H", "headers", multiple=True, help="Extra request header 'Name: Value' for URL fetches (repeatable).")
@click.option("--no-cache", is_flag=True, default=False, help="Disable caching.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Verbose logging.")
@click.option("--model", "-m", default=None, help="Model to use. Defaults per AI_PROVIDER (claude-opus-4-8 for anthropic; gemini-2.5-flash when AI_PROVIDER=gemini).")
@click.option("--chunk-delay", default=5, type=int, show_default=True, help="Seconds to wait between chunk API calls.")
@click.option("--dry-run", is_flag=True, default=False, help="Run the full pipeline without calling the AI API (mock response) to test fetch/chunk/merge/report.")
def analyze(url, url_list, file_path, dir_path, domain, output, html_out, regex_endpoints,
            offline_only, skip_libs, concurrency, proxy, insecure, headers, no_cache,
            verbose, model, chunk_delay, dry_run):
    """Analyze JavaScript files for secrets, endpoints, and vulnerabilities."""
    urls = list(url)
    if url_list:
        urls.extend(_read_url_list(url_list))
    # De-duplicate while preserving order — recon URL lists are full of repeats.
    urls = list(dict.fromkeys(urls))

    if not (urls or file_path or dir_path):
        raise click.UsageError("Provide at least one of --url/--url-list, --file, or --dir.")
    if concurrency < 1:
        raise click.UsageError("--concurrency must be >= 1.")

    logger = get_logger("js-oracle", verbose=verbose)
    console = Console()

    if skip_libs and urls:
        before = len(urls)
        urls = [u for u in urls if not is_known_library(u)]
        if before - len(urls):
            logger.info(f"--skip-libs: skipped {before - len(urls)} known-library URL(s).")

    try:
        header_map = _parse_headers(headers)
    except ValueError as e:
        raise click.UsageError(str(e))

    fetcher = JSFetcher(proxy=proxy, extra_headers=header_map, verify=not insecure)
    # Parallel runs suppress per-source tables (they would interleave); the batch
    # summary and the written reports carry the detail instead.
    reporter = ReportGenerator(output_dir=output, html=html_out, quiet=concurrency > 1)
    use_cache = not no_cache
    target = domain or ""

    def _pipeline(source_name: str, content: str):
        try:
            merged = run_pipeline(
                source_name, content, target, reporter, console,
                use_cache, logger, model, chunk_delay, dry_run, regex_endpoints, offline_only,
            )
            return (source_name, merged)
        except Exception as e:
            logger.error(f"Failed to analyze '{source_name}': {e}")
            if verbose:
                console.print_exception()
            return (source_name, None)

    def _url_task(u: str):
        try:
            content = fetcher.fetch_url(u)
        except Exception as e:
            logger.error(f"Failed to fetch '{u}': {e}")
            return (u, None)
        return _pipeline(u, content)

    def _file_task(path: str):
        try:
            content = fetcher.fetch_file(path)
        except Exception as e:
            logger.error(f"Failed to read '{path}': {e}")
            return (path, None)
        return _pipeline(path, content)

    # Build a flat list of jobs; each returns (source_name, merged | None).
    tasks = [functools.partial(_url_task, u) for u in urls]
    if file_path:
        tasks.append(functools.partial(_file_task, file_path))
    if dir_path:
        try:
            files = fetcher.fetch_directory(dir_path)
        except Exception as e:
            logger.error(f"Failed to read directory '{dir_path}': {e}")
            files = {}
        if skip_libs:
            files = {rel: c for rel, c in files.items() if not is_known_library(rel)}
        if not files:
            console.print("[yellow]No JS files found in directory.[/yellow]")
        else:
            console.print(f"[cyan]Found {len(files)} JS file(s) in directory.[/cyan]")
            tasks += [functools.partial(_pipeline, rel, content) for rel, content in files.items()]

    if not tasks:
        raise SystemExit(1)

    # Nudge on spend before a large AI batch (minified bundles are token-heavy).
    if not (offline_only or dry_run) and len(tasks) >= 15:
        console.print(
            f"[yellow]Heads-up: sending {len(tasks)} source(s) to the AI. Minified bundles are "
            f"token-heavy — for a cheaper run consider --offline (free triage), --skip-libs, "
            f"AI_PROVIDER=gemini (free tier), or --model claude-haiku-4-5.[/yellow]"
        )

    results: list[tuple[str, dict]] = []
    try:
        if concurrency > 1 and len(tasks) > 1:
            console.print(f"[cyan]Analyzing {len(tasks)} source(s), concurrency={concurrency}.[/cyan]")
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                for name, merged in pool.map(lambda job: job(), tasks):
                    if merged is not None:
                        results.append((name, merged))
        else:
            for job in tasks:
                name, merged = job()
                if merged is not None:
                    results.append((name, merged))
    except KeyboardInterrupt:
        console.print("\n[yellow]Aborted by user.[/yellow]")

    if len(results) > 1:
        _print_batch_summary(console, results)

    if html_out and results:
        index = reporter.save_batch_index(results)
        console.print(f"[green]Batch HTML index: {index}[/green]")

    if not results:
        raise SystemExit(1)


@cli.command()
@click.option("--domain", "-d", default=None, help="Target domain to crawl, e.g. example.com (discovers .js automatically).")
@click.option("--list", "-l", "list_path", default=None, help="File of seed URLs (pages or .js), one per line ('-' reads stdin).")
@click.option("--depth", default=2, type=int, show_default=True, help="Crawl depth for link-following (0 = only fetch the seeds).")
@click.option("--max-pages", default=200, type=int, show_default=True, help="Maximum number of pages to crawl.")
@click.option("--subs/--no-subs", "include_subdomains", default=True, show_default=True, help="Include subdomains of the target in scope.")
@click.option("--render", "render", is_flag=True, default=False, help="Use a headless browser to render pages — finds JS in SPAs (React/Vue/Angular) that plain crawling misses. Needs 'pip install playwright'.")
@click.option("--render-wait", default=2000, type=int, show_default=True, help="Milliseconds to wait for lazy JS after each page loads (with --render).")
@click.option("--sitemap/--no-sitemap", "use_sitemap", default=True, show_default=True, help="Also seed the crawl from robots.txt and sitemap.xml.")
@click.option("--wayback", is_flag=True, default=False, help="Also pull historic .js URLs from the Wayback Machine.")
@click.option("--domain-filter", default=None, help="Domain used to filter third-party endpoints (defaults to --domain).")
@click.option("--output", "-o", default="./reports", show_default=True, help="Output directory for reports.")
@click.option("--html", "html_out", is_flag=True, default=False, help="Also write a styled HTML report per source, plus a batch index.html.")
@click.option("--regex-endpoints", is_flag=True, default=False, help="Add an offline LinkFinder-style endpoint/URL sweep (noisier, deterministic).")
@click.option("--offline", "offline_only", is_flag=True, default=False, help="Deterministic scan only — no AI call, no API key, no cost.")
@click.option("--skip-libs", is_flag=True, default=False, help="Skip well-known JS libraries (jquery, bootstrap, ...) — don't waste AI spend on vendor code.")
@click.option("--concurrency", "-c", default=5, type=int, show_default=True, help="Fetch/analyze this many sources in parallel.")
@click.option("--proxy", default=None, help="Route all HTTP through a proxy, e.g. http://127.0.0.1:8080 (Burp).")
@click.option("--insecure", is_flag=True, default=False, help="Skip TLS certificate verification.")
@click.option("--header", "-H", "headers", multiple=True, help="Extra request header 'Name: Value' (repeatable).")
@click.option("--no-cache", is_flag=True, default=False, help="Disable caching.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Verbose logging.")
@click.option("--model", "-m", default=None, help="Model to use (defaults per AI_PROVIDER).")
@click.option("--chunk-delay", default=5, type=int, show_default=True, help="Seconds to wait between chunk API calls.")
@click.option("--dry-run", is_flag=True, default=False, help="Run the pipeline without calling the AI API (mock response).")
def hunt(domain, list_path, depth, max_pages, include_subdomains, render, render_wait, use_sitemap,
         wayback, domain_filter, output, html_out, regex_endpoints, offline_only, skip_libs,
         concurrency, proxy, insecure, headers, no_cache, verbose, model, chunk_delay, dry_run):
    """All-in-one: crawl a target, discover and download its JS, then analyze it.

    \b
    Examples:
      js-oracle hunt -d example.com
      js-oracle hunt -d example.com --wayback --html
      js-oracle hunt -l urls.txt --offline
    """
    urls = _read_url_list(list_path) if list_path else []
    if not (domain or urls):
        raise click.UsageError("Provide a target with --domain/-d or a seed list with --list/-l.")
    if concurrency < 1:
        raise click.UsageError("--concurrency must be >= 1.")

    logger = get_logger("js-oracle", verbose=verbose)
    console = Console()

    try:
        header_map = _parse_headers(headers)
    except ValueError as e:
        raise click.UsageError(str(e))

    # Auto-fall back to a free offline scan when no API key is configured, so the
    # tool still produces results out of the box instead of erroring per source.
    if not (offline_only or dry_run) and not _provider_key_present():
        console.print(
            "[yellow]No AI API key detected — running a free offline scan "
            "(secrets, source maps, endpoints). Set an API key or use --offline to silence this.[/yellow]"
        )
        offline_only = True

    if render and not playwright_available():
        raise click.UsageError(
            "--render needs Playwright. Install it with: pip install playwright "
            "(then, if needed: playwright install chromium)."
        )

    fetcher = JSFetcher(proxy=proxy, extra_headers=header_map, verify=not insecure)
    seeds, scope_hosts = build_seeds(domain, urls)
    console.print(f"[cyan]Discovering JS from {len(seeds)} seed(s), scope: {', '.join(sorted(scope_hosts)) or 'any'}[/cyan]")
    if render:
        console.print("[cyan]Render mode: driving a headless browser (SPA-aware discovery).[/cyan]")

    def _discover_with(crawler, seed_list):
        """Seed from robots/sitemap (best-effort) then crawl."""
        s = list(seed_list)
        if use_sitemap:
            base = next((u for u in s if not _looks_like_js(u)), None)
            if base:
                try:
                    s += [u for u in crawler.site_seeds(base, scope_hosts) if u not in s]
                except Exception as e:
                    logger.warning(f"robots/sitemap discovery failed: {e}")
        return crawler.discover(s, scope_hosts, crawl=True)

    try:
        if render:
            with BrowserRenderer(
                proxy=proxy, verify=not insecure, extra_headers=header_map, wait_ms=render_wait
            ) as renderer:
                crawler = JSCrawler(
                    fetcher, max_depth=depth, max_pages=max_pages,
                    include_subdomains=include_subdomains, concurrency=concurrency,
                    page_fetch=renderer.fetch_page, page_workers=1,
                )
                discovery = _discover_with(crawler, seeds)
                # Fold in JS the browser fetched over the network (webpack chunks,
                # dynamic imports) that never appear as <script src> in the DOM.
                for u in sorted(renderer.captured_js):
                    if u not in discovery.js_urls:
                        discovery.js_urls.append(u)
        else:
            crawler = JSCrawler(
                fetcher, max_depth=depth, max_pages=max_pages,
                include_subdomains=include_subdomains, concurrency=concurrency,
            )
            discovery = _discover_with(crawler, seeds)

            # HTTP fallback: a bare domain defaults to https; if that reached
            # nothing, retry over http before giving up.
            if discovery.pages_crawled == 0 and domain and not urls and seeds and seeds[0].startswith("https://"):
                http_seed = "http://" + seeds[0][len("https://"):]
                logger.info(f"No pages over https — retrying {http_seed}")
                discovery = _discover_with(crawler, [http_seed])
    except Exception as e:
        logger.error(f"Crawl failed: {e}")
        if verbose:
            console.print_exception()
        raise SystemExit(1)

    if wayback and domain:
        for u in crawler.wayback_js(domain):
            if u not in discovery.js_urls:
                discovery.js_urls.append(u)

    if skip_libs:
        before = len(discovery.js_urls)
        discovery.js_urls = [u for u in discovery.js_urls if not is_known_library(u)]
        if before - len(discovery.js_urls):
            logger.info(f"--skip-libs: skipped {before - len(discovery.js_urls)} known-library URL(s).")

    console.print(
        Panel(
            f"Pages crawled: [bold]{discovery.pages_crawled}[/bold]    "
            f"JS files: [bold green]{len(discovery.js_urls)}[/bold green]    "
            f"Inline scripts: [bold]{len(discovery.inline_scripts)}[/bold]    "
            f"Parameters: [bold]{len(discovery.parameters)}[/bold]",
            title="[bold cyan]Discovery[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )

    # Persist the raw discovery so it is useful even before analysis (recon output).
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    if discovery.js_urls:
        (out_dir / "discovered_js.txt").write_text("\n".join(discovery.js_urls) + "\n", encoding="utf-8")
    if discovery.parameters:
        (out_dir / "parameters.txt").write_text("\n".join(sorted(discovery.parameters)) + "\n", encoding="utf-8")

    if discovery.source_count == 0:
        console.print("[yellow]No JavaScript discovered. Try a higher --depth, --wayback, or check scope.[/yellow]")
        raise SystemExit(1)

    reporter = ReportGenerator(output_dir=output, html=html_out, quiet=concurrency > 1)
    target = domain_filter or domain or ""

    def _pipeline(source_name: str, content: str):
        try:
            merged = run_pipeline(
                source_name, content, target, reporter, console,
                not no_cache, logger, model, chunk_delay, dry_run, regex_endpoints, offline_only,
            )
            return (source_name, merged)
        except Exception as e:
            logger.error(f"Failed to analyze '{source_name}': {e}")
            if verbose:
                console.print_exception()
            return (source_name, None)

    def _url_task(u: str):
        try:
            content = fetcher.fetch_url(u)
        except Exception as e:
            logger.error(f"Failed to fetch '{u}': {e}")
            return (u, None)
        return _pipeline(u, content)

    tasks = [functools.partial(_url_task, u) for u in discovery.js_urls]
    tasks += [functools.partial(_pipeline, name, body) for name, body in discovery.inline_scripts.items()]

    if not (offline_only or dry_run) and len(tasks) >= 15:
        console.print(
            f"[yellow]Heads-up: sending {len(tasks)} source(s) to the AI. For a cheaper run consider "
            f"--offline, --skip-libs, AI_PROVIDER=gemini (free tier), or --model claude-haiku-4-5.[/yellow]"
        )

    results: list[tuple[str, dict]] = []
    try:
        if concurrency > 1 and len(tasks) > 1:
            console.print(f"[cyan]Analyzing {len(tasks)} source(s), concurrency={concurrency}.[/cyan]")
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                for name, merged in pool.map(lambda job: job(), tasks):
                    if merged is not None:
                        results.append((name, merged))
        else:
            for job in tasks:
                name, merged = job()
                if merged is not None:
                    results.append((name, merged))
    except KeyboardInterrupt:
        console.print("\n[yellow]Aborted by user.[/yellow]")

    if len(results) > 1:
        _print_batch_summary(console, results)

    if results:
        summary_meta = {
            "target": domain or "",
            "seeds": len(seeds),
            "pages_crawled": discovery.pages_crawled,
            "js_discovered": len(discovery.js_urls),
            "inline_scripts": len(discovery.inline_scripts),
            "offline_only": offline_only,
        }
        summary_path = reporter.save_run_summary(results, summary_meta)
        console.print(f"[green]Run summary: {summary_path}[/green]")

    if html_out and results:
        index = reporter.save_batch_index(results)
        console.print(f"[green]Batch HTML index: {index}[/green]")

    console.print(f"[green]Recon artifacts saved under: {output}[/green]")

    # Discovery already succeeded (we exit earlier when nothing is found), so a
    # run that surfaced no findings is still a successful scan — exit 0 so the
    # tool composes cleanly in automation. Reports/artifacts are on disk either way.
    if not results:
        console.print("[yellow]No findings in the analyzed sources (discovery artifacts still saved).[/yellow]")


@cli.command("clear-cache")
def clear_cache():
    """Clear the local analysis cache."""
    console = Console()
    count = analysis_cache.clear()
    console.print(f"[green]Cleared {count} cached analysis file(s).[/green]")


if __name__ == "__main__":
    cli()

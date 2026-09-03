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
        logger.warning(f"Nothing to report for '{source_name}' (all analysis failed).")
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


@cli.command("clear-cache")
def clear_cache():
    """Clear the local analysis cache."""
    console = Console()
    count = analysis_cache.clear()
    console.print(f"[green]Cleared {count} cached analysis file(s).[/green]")


if __name__ == "__main__":
    cli()

"""js-oracle: CLI entry point."""

# load_dotenv() must run before any core import so that anthropic.Anthropic()
# finds ANTHROPIC_API_KEY when the module-level `analyzer` instance is created.
from dotenv import load_dotenv
load_dotenv()

import time

import click
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

from core.fetcher import JSFetcher
from core.preprocessor import preprocessor
from core.analyzer import JSAnalyzer
from core.merger import result_merger
from core.cache import analysis_cache
from output.reporter import ReportGenerator
from utils.logger import get_logger

BANNER = r"""
    _____  ___    ___  ____    ____  ____  ____  ____     ___
   (_  _) / __)  / __)(  _ \  / ___)(  _ \/ ___)(  _ \   / __)
     )(   \__ \ ( (__  )   /  \___ \ )___/\___ \ )   /  ( (__
    (__)  (___/  \___)(__)__)  (____/(__)  (____/(__)__)  \___)
"""

# Module-level console used only for the banner (before per-command consoles exist).
_banner_console = Console()


def print_banner():
    _banner_console.print(
        Panel(
            f"[bold yellow]{BANNER}[/bold yellow]\n"
            "[cyan]AI-powered JavaScript analysis tool for bug bounty hunters[/cyan]",
            border_style="bright_yellow",
            expand=False,
        )
    )


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
) -> dict | None:
    """Run the full analysis pipeline for a single JS source.

    Returns the merged results dict, or None if the pipeline failed.
    """
    logger.info(f"Analyzing: {source_name}")

    js_analyzer = JSAnalyzer(model=model)

    chunks = preprocessor.prepare(content)
    logger.info(f"Preprocessing produced {len(chunks)} chunk(s) for '{source_name}'.")

    chunk_results = []
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

    if not chunk_results:
        logger.warning(f"All chunks failed for '{source_name}'. No results to report.")
        return None

    merged = result_merger.merge(chunk_results)

    if target_domain:
        merged = result_merger.filter_third_party(merged, target_domain)

    paths = reporter.render(merged, source_name)
    logger.info(f"Reports saved to: {paths['markdown_path']}")
    return merged


@click.group()
def cli():
    """AI-powered JavaScript analysis tool for bug bounty hunters."""
    print_banner()


@cli.command()
@click.option("--url", "-u", default=None, help="Single JS file URL to analyze.")
@click.option("--file", "-f", "file_path", default=None, help="Local JS file path.")
@click.option("--dir", "-d", "dir_path", default=None, help="Directory of JS files.")
@click.option("--domain", default=None, help="Target domain for filtering third-party endpoints.")
@click.option("--output", "-o", default="./reports", show_default=True, help="Output directory for reports.")
@click.option("--no-cache", is_flag=True, default=False, help="Disable caching.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Verbose logging.")
@click.option("--model", "-m", default=None, help="Model to use. Defaults per AI_PROVIDER (gemini-2.5-flash, or claude-sonnet-4-6 when AI_PROVIDER=anthropic).")
@click.option("--chunk-delay", default=5, type=int, show_default=True, help="Seconds to wait between chunk API calls (default: 5).")
@click.option("--dry-run", is_flag=True, default=False, help="Run the full pipeline without calling the AI API. Uses a mock response to test fetch/chunk/merge/report.")
def analyze(url, file_path, dir_path, domain, output, no_cache, verbose, model, chunk_delay, dry_run):
    """Analyze JavaScript files for secrets, endpoints, and vulnerabilities."""
    if not any([url, file_path, dir_path]):
        raise click.UsageError("Provide at least one of --url, --file, or --dir.")

    logger = get_logger("js-oracle", verbose=verbose)
    console = Console()

    fetcher = JSFetcher()
    reporter = ReportGenerator(output_dir=output)
    use_cache = not no_cache

    try:
        if url:
            content = fetcher.fetch_url(url)
            run_pipeline(url, content, domain or "", reporter, console, use_cache, logger, model, chunk_delay, dry_run)

        elif file_path:
            content = fetcher.fetch_file(file_path)
            run_pipeline(file_path, content, domain or "", reporter, console, use_cache, logger, model, chunk_delay, dry_run)

        elif dir_path:
            files = fetcher.fetch_directory(dir_path)
            if not files:
                console.print("[yellow]No JS files found in directory.[/yellow]")
                return

            console.print(f"[cyan]Found {len(files)} JS file(s). Starting batch analysis.[/cyan]")
            for rel_name, content in files.items():
                run_pipeline(rel_name, content, domain or "", reporter, console, use_cache, logger, model, chunk_delay, dry_run)

    except KeyboardInterrupt:
        console.print("\n[yellow]Aborted by user.[/yellow]")
    except Exception as e:
        logger.error(f"Pipeline failed: {e}")
        if verbose:
            console.print_exception()


@cli.command("clear-cache")
def clear_cache():
    """Clear the local analysis cache."""
    console = Console()
    count = analysis_cache.clear()
    console.print(f"[green]Cleared {count} cached analysis file(s).[/green]")


if __name__ == "__main__":
    cli()

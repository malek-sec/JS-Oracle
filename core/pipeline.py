"""Reusable analysis core shared by the CLI and the HTTP service.

Given already-fetched JavaScript *content*, run the same pipeline the CLI uses —
preprocess (beautify + chunk) -> LLM analyze each chunk -> merge with the free
offline scan -> filter third-party — and return the merged findings dict.

Deliberately does NO fetching and NO report writing: those stay with the caller
(the CLI's reporter, or the service's JSON response), so this function is a pure
`content -> findings` transform that both entry points can share without
duplicating the merge/offline/filter logic. `main.py` keeps its own richer
`run_pipeline` (chunk pacing, per-source reporting); this is the slim core the
FastAPI service in `service.py` builds on.
"""

from core.analyzer import JSAnalyzer
from core.merger import result_merger
from core.patterns import offline_findings
from core.preprocessor import preprocessor
from utils.logger import logger


def analyze_source(
    content: str,
    target_domain: str = "",
    *,
    model: str | None = None,
    use_cache: bool = True,
    dry_run: bool = False,
    regex_endpoints: bool = False,
) -> dict:
    """Analyze raw JS ``content`` and return the merged findings dict.

    Mirrors ``main.run_pipeline`` minus fetching and reporting. The offline
    deterministic scan runs on the FULL content and is merged alongside the LLM
    chunks, so secrets/source-maps are reported even if a chunk analysis fails.
    """
    analyzer = JSAnalyzer(model=model)

    chunks = preprocessor.prepare(content)
    logger.info(f"analyze_source: {len(chunks)} chunk(s), {len(content):,} chars.")

    chunk_results: list[dict] = []
    for idx, chunk in enumerate(chunks, start=1):
        try:
            chunk_results.append(
                analyzer.analyze(chunk, target_domain, use_cache, dry_run=dry_run))
        except Exception as exc:  # one bad chunk must not sink the whole file
            logger.error(f"analyze_source: chunk {idx}/{len(chunks)} failed: {exc}")

    offline = offline_findings(content, include_endpoints=regex_endpoints)
    if offline["secrets"] or offline["endpoints"] or offline["suspicious_logic"]:
        chunk_results.append(offline)

    merged = result_merger.merge(chunk_results)
    if target_domain:
        merged = result_merger.filter_third_party(merged, target_domain)
    return merged

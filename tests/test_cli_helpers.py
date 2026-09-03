"""Tests for CLI helpers and the offline-only pipeline."""

import pytest
from rich.console import Console

from main import _parse_headers, _read_url_list, run_pipeline
from output.reporter import ReportGenerator
from utils.logger import get_logger


def test_parse_headers_valid():
    out = _parse_headers(("Authorization: Bearer abc", "X-Env:staging"))
    assert out == {"Authorization": "Bearer abc", "X-Env": "staging"}


def test_parse_headers_empty_tuple():
    assert _parse_headers(()) == {}


def test_parse_headers_rejects_missing_colon():
    with pytest.raises(ValueError, match="Expected 'Name: Value'"):
        _parse_headers(("NoColonHere",))


def test_parse_headers_rejects_empty_name():
    with pytest.raises(ValueError, match="Empty header name"):
        _parse_headers((": value",))


def test_read_url_list_skips_blanks_and_comments(tmp_path):
    f = tmp_path / "urls.txt"
    f.write_text(
        "https://a.com/app.js\n"
        "\n"
        "# a comment\n"
        "  https://b.com/main.js  \n",
        encoding="utf-8",
    )
    assert _read_url_list(str(f)) == ["https://a.com/app.js", "https://b.com/main.js"]


def test_read_url_list_missing_file_raises(tmp_path):
    import click
    with pytest.raises(click.UsageError):
        _read_url_list(str(tmp_path / "nope.txt"))


def test_offline_only_pipeline_needs_no_api(tmp_path):
    # --offline must run the deterministic scan and produce a report without ever
    # constructing an AI client or needing a key.
    reporter = ReportGenerator(output_dir=str(tmp_path))
    logger = get_logger("test-offline", verbose=False)
    content = 'var ip = "10.0.0.5";\n//# sourceMappingURL=app.js.map\n'
    merged = run_pipeline(
        "app.js", content, "", reporter, Console(),
        use_cache=False, logger=logger, offline_only=True,
    )
    assert merged is not None
    assert merged["analysis_summary"]["total_findings"] >= 2  # source map + internal IP
    assert any(s["type"] == "internal_ip" for s in merged["secrets"])

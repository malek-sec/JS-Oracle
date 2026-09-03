"""Tests for report filename safety and Markdown cell escaping."""

from output.reporter import ReportGenerator


def test_report_basename_is_unique_for_colliding_slugs(tmp_path):
    rg = ReportGenerator(output_dir=str(tmp_path))
    # Two distinct sources whose first 80 slug chars are identical.
    long_prefix = "https://cdn.example.com/" + "a" * 120
    name_a = long_prefix + "/one.js"
    name_b = long_prefix + "/two.js"
    base_a = rg._report_basename(name_a)
    base_b = rg._report_basename(name_b)
    assert base_a != base_b  # must not overwrite each other


def test_md_cell_escapes_pipes_and_newlines():
    rg = ReportGenerator(output_dir=".")
    assert rg._md_cell("a|b") == "a\\|b"
    assert rg._md_cell("line1\nline2") == "line1 line2"
    assert rg._md_cell("x\r\ny") == "x y"
    assert rg._md_cell(None) == ""


def test_markdown_table_stays_intact_with_pipe_in_evidence(tmp_path):
    rg = ReportGenerator(output_dir=str(tmp_path))
    results = {
        "analysis_summary": {"total_findings": 1, "highest_severity": "high"},
        "endpoints": [],
        "secrets": [{"type": "token", "value_preview": "abc***",
                     "evidence": "authorization: Bearer x || fallback"}],
        "auth_logic": [],
        "suspicious_logic": [],
    }
    md_path = rg._save_markdown(results, "sample.js")
    content = open(md_path, encoding="utf-8").read()
    # The raw pipe must be escaped so it doesn't spawn a phantom column.
    assert "x \\|\\| fallback" in content


def test_html_report_written_and_escapes(tmp_path):
    rg = ReportGenerator(output_dir=str(tmp_path), html=True)
    results = {
        "analysis_summary": {"total_findings": 1, "highest_severity": "high"},
        "endpoints": [{"path": "/api/<x>", "method": "GET", "parameters": [],
                       "body_structure": None, "evidence": "a<b>", "confidence": "high"}],
        "secrets": [], "auth_logic": [], "suspicious_logic": [],
    }
    paths = rg.render(results, "sample.js")
    assert "html_path" in paths
    html_doc = open(paths["html_path"], encoding="utf-8").read()
    assert "<!doctype html>" in html_doc.lower()
    # Angle brackets from finding values must be HTML-escaped, not raw.
    assert "&lt;x&gt;" in html_doc
    assert "<x>" not in html_doc


def test_render_without_html_flag_has_no_html_path(tmp_path):
    rg = ReportGenerator(output_dir=str(tmp_path))  # html defaults to False
    results = {
        "analysis_summary": {"total_findings": 0, "highest_severity": "none"},
        "endpoints": [], "secrets": [], "auth_logic": [], "suspicious_logic": [],
    }
    paths = rg.render(results, "s.js")
    assert "html_path" not in paths


def test_batch_index_links_sources(tmp_path):
    rg = ReportGenerator(output_dir=str(tmp_path), html=True)
    merged = {
        "analysis_summary": {"total_findings": 2, "highest_severity": "medium"},
        "endpoints": [{}], "secrets": [{}], "auth_logic": [], "suspicious_logic": [],
    }
    index = rg.save_batch_index([("a.js", merged), ("b.js", merged)])
    doc = open(index, encoding="utf-8").read()
    assert "Batch Report" in doc
    assert ".html" in doc  # links to per-source reports

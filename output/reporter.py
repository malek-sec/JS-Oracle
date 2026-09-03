"""Formats and renders analysis results to various output formats."""

import hashlib
import html
import json
import re
from datetime import datetime
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from utils.logger import logger


class ReportGenerator:

    def __init__(self, output_dir: str = "./reports", html: bool = False, quiet: bool = False):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.console = Console()
        self.html = html      # also emit a styled .html report per source + a batch index
        self.quiet = quiet    # suppress per-source terminal tables (used in concurrent mode)

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def render(self, results: dict, source_name: str) -> dict:
        """Orchestrate terminal display, Markdown, JSON (and optional HTML) output.

        Returns a dict of written paths: always ``markdown_path`` and
        ``json_path``; ``html_path`` too when HTML output is enabled.
        """
        if not self.quiet:
            self._print_terminal(results, source_name)
        md_path = self._save_markdown(results, source_name)
        json_path = self._save_json(results, source_name)
        paths = {"markdown_path": md_path, "json_path": json_path}
        if self.html:
            paths["html_path"] = self._save_html(results, source_name)
        logger.info(f"Reports saved — markdown: {md_path}, json: {json_path}")
        return paths

    # -------------------------------------------------------------------------
    # Terminal output
    # -------------------------------------------------------------------------

    def _print_terminal(self, results: dict, source_name: str) -> None:
        summary = results.get("analysis_summary", {})
        total = summary.get("total_findings", 0)
        severity = summary.get("highest_severity", "none")
        sev_style = self._severity_style(severity)

        self.console.print(
            Panel(
                f"[bold]{source_name}[/bold]\n"
                f"Total findings: [bold]{total}[/bold]  |  "
                f"Highest severity: [{sev_style}]{severity.upper()}[/{sev_style}]",
                title="[bold cyan]JS Oracle — Analysis Report[/bold cyan]",
                border_style="cyan",
                expand=False,
            )
        )

        endpoints = results.get("endpoints", [])
        if endpoints:
            self.console.print()
            tbl = Table(title="Endpoints", box=box.ROUNDED, show_lines=True)
            tbl.add_column("Method", style="bold", no_wrap=True)
            tbl.add_column("Path")
            tbl.add_column("Confidence", no_wrap=True)
            tbl.add_column("Evidence")

            conf_style = {"high": "green", "medium": "yellow", "low": "dim"}
            for ep in endpoints:
                conf = ep.get("confidence", "low")
                cs = conf_style.get(conf, "white")
                tbl.add_row(
                    ep.get("method", "UNKNOWN"),
                    ep.get("path", ""),
                    f"[{cs}]{conf}[/{cs}]",
                    self._truncate(ep.get("evidence", "")),
                )
            self.console.print(tbl)

        secrets = results.get("secrets", [])
        if secrets:
            self.console.print()
            tbl = Table(title="Secrets", box=box.ROUNDED, show_lines=True)
            tbl.add_column("Type", style="bold red", no_wrap=True)
            tbl.add_column("Preview", no_wrap=True)
            tbl.add_column("Evidence")
            for s in secrets:
                tbl.add_row(
                    s.get("type", ""),
                    s.get("value_preview", ""),
                    self._truncate(s.get("evidence", "")),
                )
            self.console.print(tbl)

        auth_logic = results.get("auth_logic", [])
        if auth_logic:
            self.console.print()
            tbl = Table(title="Authentication Logic", box=box.ROUNDED, show_lines=True)
            tbl.add_column("Storage", style="bold", no_wrap=True)
            tbl.add_column("Mechanism")
            tbl.add_column("Evidence")
            for a in auth_logic:
                tbl.add_row(
                    a.get("storage_location", ""),
                    a.get("mechanism", ""),
                    self._truncate(a.get("evidence", "")),
                )
            self.console.print(tbl)

        suspicious = results.get("suspicious_logic", [])
        if suspicious:
            self.console.print()
            tbl = Table(title="Suspicious Logic", box=box.ROUNDED, show_lines=True)
            tbl.add_column("Severity", no_wrap=True)
            tbl.add_column("Description")
            tbl.add_column("Evidence")
            for item in suspicious:
                sev = item.get("severity", "info")
                ss = self._severity_style(sev)
                tbl.add_row(
                    f"[{ss}]{sev.upper()}[/{ss}]",
                    item.get("description", ""),
                    self._truncate(item.get("evidence", "")),
                )
            self.console.print(tbl)

    # -------------------------------------------------------------------------
    # File output
    # -------------------------------------------------------------------------

    def _save_markdown(self, results: dict, source_name: str) -> str:
        summary = results.get("analysis_summary", {})
        total = summary.get("total_findings", 0)
        severity = summary.get("highest_severity", "none")
        timestamp = datetime.now().isoformat(timespec="seconds")

        lines: list[str] = [
            "# JS Oracle Analysis Report",
            "",
            f"**Source:** {source_name}",
            f"**Generated:** {timestamp}",
            f"**Total findings:** {total}",
            f"**Highest severity:** {severity}",
        ]

        endpoints = results.get("endpoints", [])
        if endpoints:
            lines += [
                "",
                "## Endpoints",
                "",
                "| Method | Path | Parameters | Confidence |",
                "|--------|------|------------|------------|",
            ]
            for ep in endpoints:
                params = ", ".join(ep.get("parameters") or []) or "—"
                lines.append(
                    f"| {self._md_cell(ep.get('method', 'UNKNOWN'))} "
                    f"| {self._md_cell(ep.get('path', ''))} "
                    f"| {self._md_cell(params)} "
                    f"| {self._md_cell(ep.get('confidence', ''))} |"
                )
            lines += ["", "### Evidence details", ""]
            for ep in endpoints:
                path = self._md_cell(ep.get("path", "")).replace("`", "'")
                evidence = self._md_cell(ep.get("evidence", "")).replace("`", "'")
                lines.append(f"- `{path}` — `{evidence}`")

        secrets = results.get("secrets", [])
        if secrets:
            lines += [
                "",
                "## Secrets",
                "",
                "| Type | Preview | Evidence |",
                "|------|---------|----------|",
            ]
            for s in secrets:
                lines.append(
                    f"| {self._md_cell(s.get('type', ''))} "
                    f"| `{self._md_cell(s.get('value_preview', ''))}` "
                    f"| {self._md_cell(s.get('evidence', ''))} |"
                )

        auth_logic = results.get("auth_logic", [])
        if auth_logic:
            lines += [
                "",
                "## Authentication Logic",
                "",
                "| Mechanism | Storage | Evidence |",
                "|-----------|---------|----------|",
            ]
            for a in auth_logic:
                lines.append(
                    f"| {self._md_cell(a.get('mechanism', ''))} "
                    f"| {self._md_cell(a.get('storage_location', ''))} "
                    f"| {self._md_cell(a.get('evidence', ''))} |"
                )

        suspicious = results.get("suspicious_logic", [])
        if suspicious:
            lines += [
                "",
                "## Suspicious Logic",
                "",
                "| Severity | Description | Evidence |",
                "|----------|-------------|----------|",
            ]
            for item in suspicious:
                lines.append(
                    f"| {self._md_cell(item.get('severity', '').upper())} "
                    f"| {self._md_cell(item.get('description', ''))} "
                    f"| {self._md_cell(item.get('evidence', ''))} |"
                )

        path = self.output_dir / (self._report_basename(source_name) + ".md")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return str(path)

    def _save_json(self, results: dict, source_name: str) -> str:
        path = self.output_dir / (self._report_basename(source_name) + ".json")
        path.write_text(
            json.dumps(results, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return str(path)

    # -------------------------------------------------------------------------
    # HTML output
    # -------------------------------------------------------------------------

    _HTML_CSS = """
:root{--bg:#f7f7f8;--fg:#1c1c1e;--muted:#6b6b70;--card:#fff;--border:#e3e3e6;--accent:#0b74de}
@media(prefers-color-scheme:dark){:root{--bg:#161618;--fg:#e8e8ea;--muted:#9a9aa0;--card:#1f1f22;--border:#333}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 10px}
.meta{color:var(--muted);font-size:13px;margin-bottom:18px;word-break:break-all}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:14px 0}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px 16px;min-width:120px}
.card .n{font-size:22px;font-weight:700}.card .l{color:var(--muted);font-size:12px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);
border-radius:10px;overflow:hidden;font-size:13px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-word}
th{background:rgba(127,127,127,.08);font-weight:600}tr:last-child td{border-bottom:none}
code{background:rgba(127,127,127,.12);padding:1px 5px;border-radius:5px;font-size:12px}
.sev{display:inline-block;padding:1px 8px;border-radius:20px;font-size:11px;font-weight:700;color:#fff}
.sev-critical{background:#b00020}.sev-high{background:#e5484d}.sev-medium{background:#d9822b}
.sev-low{background:#0b74de}.sev-info{background:#6b6b70}.sev-none{background:#2e7d32}
.empty{color:var(--muted)}a{color:var(--accent)}
"""

    def _sev_badge(self, sev: str) -> str:
        sev = (sev or "none").lower()
        return f'<span class="sev sev-{html.escape(sev)}">{html.escape(sev.upper())}</span>'

    def _html_table(self, headers: list[str], rows: list[list[str]]) -> str:
        if not rows:
            return '<p class="empty">None found.</p>'
        head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
        body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
        return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"

    def _save_html(self, results: dict, source_name: str) -> str:
        e = html.escape
        summary = results.get("analysis_summary", {})
        total = summary.get("total_findings", 0)
        severity = summary.get("highest_severity", "none")
        endpoints = results.get("endpoints", [])
        secrets = results.get("secrets", [])
        auth = results.get("auth_logic", [])
        suspicious = results.get("suspicious_logic", [])

        ep_rows = [
            [e(x.get("method", "UNKNOWN")), f"<code>{e(x.get('path', ''))}</code>",
             e(", ".join(x.get("parameters") or []) or "—"), e(x.get("confidence", "")),
             f"<code>{e(x.get('evidence', ''))}</code>"]
            for x in endpoints
        ]
        sec_rows = [
            [e(x.get("type", "")), f"<code>{e(x.get('value_preview', ''))}</code>",
             f"<code>{e(x.get('evidence', ''))}</code>"]
            for x in secrets
        ]
        auth_rows = [
            [e(x.get("mechanism", "")), e(x.get("storage_location", "")),
             f"<code>{e(x.get('evidence', ''))}</code>"]
            for x in auth
        ]
        sus_rows = [
            [self._sev_badge(x.get("severity", "info")), e(x.get("description", "")),
             f"<code>{e(x.get('evidence', ''))}</code>"]
            for x in suspicious
        ]

        doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JS Oracle — {e(Path(source_name).name)}</title>
<style>{self._HTML_CSS}</style></head><body><div class="wrap">
<h1>JS Oracle — Analysis Report</h1>
<div class="meta">Source: {e(source_name)}<br>Generated: {e(datetime.now().isoformat(timespec="seconds"))}</div>
<div class="cards">
<div class="card"><div class="n">{total}</div><div class="l">Total findings</div></div>
<div class="card"><div class="n">{self._sev_badge(severity)}</div><div class="l">Highest severity</div></div>
<div class="card"><div class="n">{len(endpoints)}</div><div class="l">Endpoints</div></div>
<div class="card"><div class="n">{len(secrets)}</div><div class="l">Secrets</div></div>
<div class="card"><div class="n">{len(auth)}</div><div class="l">Auth logic</div></div>
<div class="card"><div class="n">{len(suspicious)}</div><div class="l">Suspicious</div></div>
</div>
<h2>Endpoints</h2>{self._html_table(["Method", "Path", "Parameters", "Confidence", "Evidence"], ep_rows)}
<h2>Secrets</h2>{self._html_table(["Type", "Preview", "Evidence"], sec_rows)}
<h2>Authentication Logic</h2>{self._html_table(["Mechanism", "Storage", "Evidence"], auth_rows)}
<h2>Suspicious Logic</h2>{self._html_table(["Severity", "Description", "Evidence"], sus_rows)}
</div></body></html>
"""
        path = self.output_dir / (self._report_basename(source_name) + ".html")
        path.write_text(doc, encoding="utf-8")
        return str(path)

    def save_batch_index(self, results: list) -> str:
        """Write an index.html dashboard linking every source's HTML report.

        ``results`` is a list of ``(source_name, merged_dict)`` tuples.
        """
        e = html.escape
        rows = []
        for source_name, merged in results:
            summ = merged.get("analysis_summary", {})
            sev = summ.get("highest_severity", "none")
            base = self._report_basename(source_name)
            rows.append([
                f'<a href="{e(base)}.html">{e(source_name)}</a>',
                self._sev_badge(sev),
                str(summ.get("total_findings", 0)),
                str(len(merged.get("endpoints", []))),
                str(len(merged.get("secrets", []))),
                str(len(merged.get("suspicious_logic", []))),
            ])
        doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JS Oracle — Batch Report</title>
<style>{self._HTML_CSS}</style></head><body><div class="wrap">
<h1>JS Oracle — Batch Report</h1>
<div class="meta">{len(results)} source(s) · Generated: {e(datetime.now().isoformat(timespec="seconds"))}</div>
{self._html_table(["Source", "Highest severity", "Findings", "Endpoints", "Secrets", "Suspicious"], rows)}
</div></body></html>
"""
        path = self.output_dir / "index.html"
        path.write_text(doc, encoding="utf-8")
        return str(path)

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _slugify(self, text: str) -> str:
        slug = text.lower()
        slug = re.sub(r"[^a-z0-9]+", "_", slug)
        slug = re.sub(r"_+", "_", slug)
        slug = slug.strip("_")
        return slug[:80]

    def _report_basename(self, source_name: str) -> str:
        """Build a filesystem-safe, collision-free basename for a source.

        Two different sources can slugify to the same 80-char string (e.g. long
        URLs sharing a prefix), which would silently overwrite each other's
        reports. Appending a short hash of the *full* source name guarantees
        uniqueness while keeping the human-readable slug.
        """
        slug = self._slugify(Path(source_name).name) or "report"
        digest = hashlib.sha1(source_name.encode("utf-8")).hexdigest()[:8]
        return f"{slug}_{digest}"

    def _md_cell(self, value) -> str:
        """Escape a value for safe inclusion in a Markdown table cell.

        Pipes would break the column layout and newlines would break the row,
        so escape the former and collapse the latter.
        """
        text = str(value) if value is not None else ""
        text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
        return text.replace("|", "\\|")

    def _truncate(self, text: str, max_len: int = 60) -> str:
        if not text:
            return ""
        if len(text) > max_len:
            return text[: max_len - 1] + "…"
        return text

    def _severity_style(self, severity: str) -> str:
        return {
            "critical": "red bold",
            "high": "bright_red",
            "medium": "yellow",
            "low": "cyan",
            "info": "white",
            "none": "green",
        }.get(severity, "white")

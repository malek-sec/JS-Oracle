"""Formats and renders analysis results to various output formats."""

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

    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.console = Console()

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def render(self, results: dict, source_name: str) -> dict:
        """Orchestrate terminal display, Markdown, and JSON output.

        Returns:
            {"markdown_path": str, "json_path": str}
        """
        self._print_terminal(results, source_name)
        md_path = self._save_markdown(results, source_name)
        json_path = self._save_json(results, source_name)
        logger.info(f"Reports saved — markdown: {md_path}, json: {json_path}")
        return {"markdown_path": md_path, "json_path": json_path}

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
                    f"| {ep.get('method', 'UNKNOWN')} "
                    f"| {ep.get('path', '')} "
                    f"| {params} "
                    f"| {ep.get('confidence', '')} |"
                )
            lines += ["", "### Evidence details", ""]
            for ep in endpoints:
                lines.append(f"- `{ep.get('path', '')}` — `{ep.get('evidence', '')}`")

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
                ev = s.get("evidence", "").replace("|", "\\|")
                lines.append(
                    f"| {s.get('type', '')} "
                    f"| `{s.get('value_preview', '')}` "
                    f"| {ev} |"
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
                ev = a.get("evidence", "").replace("|", "\\|")
                lines.append(
                    f"| {a.get('mechanism', '')} "
                    f"| {a.get('storage_location', '')} "
                    f"| {ev} |"
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
                ev = item.get("evidence", "").replace("|", "\\|")
                lines.append(
                    f"| {item.get('severity', '').upper()} "
                    f"| {item.get('description', '')} "
                    f"| {ev} |"
                )

        path = self.output_dir / (self._slugify(Path(source_name).name) + ".md")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return str(path)

    def _save_json(self, results: dict, source_name: str) -> str:
        path = self.output_dir / (self._slugify(Path(source_name).name) + ".json")
        path.write_text(
            json.dumps(results, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
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


report_generator = ReportGenerator()

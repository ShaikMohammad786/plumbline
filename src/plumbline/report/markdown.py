"""Markdown report exporter producing PLUMBLINE_REPORT.md."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from plumbline.models import Report


def render_markdown_report(report: Report) -> str:
    """Render a comprehensive GitHub-flavored Markdown report."""
    lines: list[str] = []

    # Title & Header
    lines.append("# Plumbline Repository Audit Report")
    lines.append(f"**Root:** `{report.root}` | **Date:** {str(report.started_at)[:19]}")
    if report.git_commit:
        lines.append(f"**Git Commit:** `{report.git_commit[:8]}`")
    lines.append("")

    # Executive Scorecard
    lines.append("## Executive Scorecard")
    lines.append("")
    lines.append("| Repo Truth Score | Grade | Active Findings | Scanned Files | Duration |")
    lines.append("| :---: | :---: | :---: | :---: | :---: |")
    lines.append(
        f"| **{report.score}/100** | **{report.grade}** | **{len(report.findings)}** | {report.stats.files} | {report.stats.duration_s:.2f}s |"
    )
    lines.append("")

    # Severity Counts
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    fam_counts: dict[str, int] = {}
    for f in report.findings:
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
        fam_counts[f.family] = fam_counts.get(f.family, 0) + 1

    lines.append("### Findings Distribution")
    lines.append(
        f"- **Critical:** {sev_counts['critical']} | **High:** {sev_counts['high']} | **Medium:** {sev_counts['medium']} | **Low:** {sev_counts['low']} | **Info:** {sev_counts['info']}"
    )
    fam_str = " | ".join(f"**{fam}:** {count}" for fam, count in sorted(fam_counts.items()))
    if fam_str:
        lines.append(f"- **By Family:** {fam_str}")
    lines.append("")

    # Top Findings Table
    lines.append("## Key Findings")
    lines.append("")
    if not report.findings:
        lines.append("> [!TIP]")
        lines.append("> Clean scan! No issues found at or above configured threshold.")
        lines.append("")
    else:
        lines.append("| Severity | Rule | Location | Description & Fix Hint |")
        lines.append("| :--- | :--- | :--- | :--- |")
        sorted_findings = sorted(
            report.findings,
            key=lambda x: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                    x.severity.value, 5
                ),
                x.location.path,
                x.location.start_line,
            ),
        )
        for f in sorted_findings[:25]:
            sev_badge = f.severity.value.upper()
            loc_str = f"`{f.location.path}:{f.location.start_line}`"
            detail = f"**{f.title}**: {f.message}<br/>*Fix:* {f.fix_hint}"
            if f.llm:
                detail += f"<br/>*🤖 LLM ({f.llm.model}):* **{f.llm.verdict.upper()}** — {f.llm.rationale}"
            lines.append(f"| **{sev_badge}** | `{f.rule_id}` | {loc_str} | {detail} |")
        lines.append("")

    # Claim Ledger Table
    if report.claims:
        lines.append("## Claim Ledger (Documentation vs Code Reality)")
        lines.append("")
        lines.append("| Verdict | Category | Claim Text | Source | Evidence |")
        lines.append("| :---: | :--- | :--- | :--- | :--- |")
        for c in report.claims:
            verdict_badge = f"**{c.verdict.value}**"
            source_str = f"`{c.source.path}:{c.source.start_line}`"
            ev_list = [
                f"{e.get('path', '')}:{e.get('line', '')} ({e.get('note', '')})"
                for e in c.evidence[:2]
            ]
            ev_str = "<br/>".join(ev_list) if ev_list else "*No code evidence*"
            lines.append(
                f"| {verdict_badge} | `{c.claim_type}` | {c.text} | {source_str} | {ev_str} |"
            )
        lines.append("")

    # Score Breakdown
    if report.score_breakdown:
        lines.append("## Score Breakdown")
        lines.append("")
        lines.append("| Category / Rule | Base Penalty | Finding Count | Weighted Penalty |")
        lines.append("| :--- | :---: | :---: | :---: |")
        for cat, details in sorted(report.score_breakdown.items()):
            if isinstance(details, dict):
                lines.append(
                    f"| `{cat}` | {details.get('base', 0):.1f} | {details.get('count', 0)} | {details.get('total', 0):.1f} |"
                )
        lines.append("")

    # Footer
    lines.append("---")
    lines.append(
        "*Generated automatically by [Plumbline](https://github.com/ShaikMohammad786/plumbline).*"
    )
    return "\n".join(lines)


def write_markdown_report(report: Report, out_path: Optional[Path] = None) -> Path:
    """Render and write report to markdown file."""
    if out_path is None:
        out_path = Path("PLUMBLINE_REPORT.md")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    content = render_markdown_report(report)
    out_path.write_text(content, encoding="utf-8")
    return out_path

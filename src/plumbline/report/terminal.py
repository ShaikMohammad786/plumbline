"""Rich terminal reporting for Plumbline findings and scores."""

from __future__ import annotations

from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from plumbline.models import FindingSeverity, Report


def render_terminal_report(report: Report, console: Optional[Console] = None) -> None:
    """Render terminal report constrained to <= 100 columns."""
    c = console or Console(width=98)

    # 1. Header Banner & Score Box
    grade_color = (
        "green" if report.grade in ("A", "B") else "yellow" if report.grade == "C" else "red"
    )
    score_text = Text()
    score_text.append(f"Repo Truth Score: {report.score}/100  ", style=f"bold {grade_color}")
    score_text.append(f"Grade: {report.grade}  ", style=f"bold reverse {grade_color}")
    score_text.append(f"Duration: {report.stats.duration_s:.2f}s", style="dim")

    c.print()
    c.print(
        Panel(
            score_text,
            title="[bold blue]Plumbline Repository Audit[/bold blue]",
            border_style="blue",
        )
    )

    # 2. Findings counts by severity & family
    sev_counts = {sev: 0 for sev in FindingSeverity}
    family_counts: dict[str, int] = {}
    active_findings = [f for f in report.findings if not f.suppressed and not f.baselined]

    for f in active_findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        family_counts[f.family] = family_counts.get(f.family, 0) + 1

    summary_table = Table(box=None, padding=(0, 2), show_header=False)
    summary_table.add_row(
        f"[bold red]Critical: {sev_counts[FindingSeverity.CRITICAL]}[/bold red]",
        f"[bold bright_red]High: {sev_counts[FindingSeverity.HIGH]}[/bold bright_red]",
        f"[bold yellow]Medium: {sev_counts[FindingSeverity.MEDIUM]}[/bold yellow]",
        f"[bold cyan]Low: {sev_counts[FindingSeverity.LOW]}[/bold cyan]",
        f"[bold dim]Total Active: {len(active_findings)}[/bold dim]",
    )
    c.print(summary_table)
    c.print()

    # 3. Top Findings Table
    if active_findings:
        findings_table = Table(
            title="[bold]Top Findings (Highest Risk)[/bold]",
            title_justify="left",
            show_header=True,
            header_style="bold magenta",
        )
        findings_table.add_column("Rule", style="bold cyan", width=10)
        findings_table.add_column("Sev", style="white", width=8)
        findings_table.add_column("Location", style="dim", width=26)
        findings_table.add_column("Details & Fix Hint", style="white")

        # Sort active findings by severity weight
        sev_order = {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 3,
            FindingSeverity.INFO: 4,
        }
        sorted_findings = sorted(active_findings, key=lambda f: sev_order.get(f.severity, 9))

        for f in sorted_findings[:10]:
            sev_style = (
                "bold red"
                if f.severity == FindingSeverity.CRITICAL
                else "bright_red"
                if f.severity == FindingSeverity.HIGH
                else "yellow"
                if f.severity == FindingSeverity.MEDIUM
                else "cyan"
            )
            loc_str = f"{f.location.path}:{f.location.start_line}"
            detail_text = f"{f.message}\n[dim]Fix: {f.fix_hint}[/dim]"

            findings_table.add_row(
                f.rule_id,
                f"[{sev_style}]{f.severity.value}[/{sev_style}]",
                loc_str,
                detail_text,
            )

        c.print(findings_table)
        if len(sorted_findings) > 10:
            c.print(
                f"[dim]... and {len(sorted_findings) - 10} more findings (view in full JSON or HTML report).[/dim]"
            )
    else:
        c.print(
            "[bold green]✔ Zero active findings detected! Codebase meets all checked truth standards.[/bold green]"
        )

    # 4. Claim Ledger Table
    if report.claims:
        c.print()
        claims_table = Table(
            title="Claim Ledger (Documentation vs Code Reality)",
            box=box.ROUNDED,
            expand=True,
            header_style="bold magenta",
        )
        claims_table.add_column("Verdict", style="bold", width=14)
        claims_table.add_column("Category", width=16)
        claims_table.add_column("Documented Claim", ratio=3)
        claims_table.add_column("Source", width=22)

        verdict_styles = {
            "VERIFIED": "bold green",
            "PARTIAL": "bold yellow",
            "UNSUPPORTED": "bold red",
            "CONTRADICTED": "bold bright_red",
            "UNCHECKED": "dim",
        }
        for clm in report.claims[:10]:
            v_style = verdict_styles.get(clm.verdict.value, "white")
            loc_str = f"{clm.source.path}:{clm.source.start_line}"
            claims_table.add_row(
                f"[{v_style}]{clm.verdict.value}[/{v_style}]",
                clm.claim_type,
                clm.text,
                loc_str,
            )
        c.print(claims_table)
        if len(report.claims) > 10:
            c.print(
                f"[dim]... and {len(report.claims) - 10} more claims (view in HTML or JSON report).[/dim]"
            )

    # 5. Baselines & Suppressions Summary
    suppressed_count = sum(1 for f in report.findings if f.suppressed)
    baselined_count = sum(1 for f in report.findings if f.baselined)
    if suppressed_count > 0 or baselined_count > 0:
        c.print(
            f"\n[dim]Ignored: {suppressed_count} inline suppressions, {baselined_count} baselined.[/dim]"
        )

    # 5. Footer with next command
    c.print()
    if active_findings:
        c.print(
            "[bold blue]Next steps:[/bold blue] Run [cyan]plumb explain <RULE_ID>[/cyan] or suppress with [dim]plumbline:ignore[RULE_ID] <reason>[/dim]"
        )
    else:
        c.print(
            "[bold blue]Next steps:[/bold blue] Run [cyan]plumb baseline create[/cyan] to freeze current state."
        )

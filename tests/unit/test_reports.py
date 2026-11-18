"""Tests for report exporters: Markdown, HTML standalone, JSON, and SARIF."""

import datetime
from pathlib import Path

from plumbline.models import (
    Claim,
    ClaimVerdict,
    Evidence,
    FileClass,
    Finding,
    FindingConfidence,
    FindingSeverity,
    Location,
    Report,
    ScanStats,
)
from plumbline.report.html import render_html_report, write_html_report
from plumbline.report.markdown import render_markdown_report, write_markdown_report


def _create_sample_report() -> Report:
    finding = Finding(
        id="abc123def456",
        rule_id="SEC001",
        family="SEC",
        title="Hardcoded credential detected",
        message="Hardcoded Stripe Secret Key detected in source file.",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        location=Location(path="src/app.py", start_line=10, end_line=10),
        evidence=Evidence(snippet='STRIPE_KEY = "sk_t********************"'),
        fix_hint="Extract secret to environment variables.",
        file_class=FileClass.PROD,
    )
    claim = Claim(
        id="claim123",
        text="This service provides JWT user authentication.",
        source=Location(path="README.md", start_line=5, end_line=5),
        claim_type="authentication",
        verdict=ClaimVerdict.VERIFIED,
        evidence=[{"path": "src/auth.py", "line": 12, "note": "Imported module 'jwt'"}],
        confidence=FindingConfidence.HIGH,
    )
    return Report(
        started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        root="/workspace/demo",
        stats=ScanStats(files=15, lines=1200, duration_s=0.25),
        findings=[finding],
        claims=[claim],
        score=92,
        grade="A",
        score_breakdown={"SEC": {"base": 20.0, "count": 1, "total": 20.0}},
    )


def test_markdown_report_generation(tmp_path: Path) -> None:
    """Markdown report contains scorecard, findings, and claim ledger table."""
    report = _create_sample_report()
    md_content = render_markdown_report(report)

    assert "# Plumbline Repository Audit Report" in md_content
    assert "92/100" in md_content
    assert "Grade A" in md_content or "**A**" in md_content
    assert "SEC001" in md_content
    assert "Claim Ledger" in md_content
    assert "JWT user authentication" in md_content
    assert "VERIFIED" in md_content

    out_file = tmp_path / "PLUMBLINE_REPORT.md"
    written_path = write_markdown_report(report, out_file)
    assert written_path.exists()
    assert written_path.read_text(encoding="utf-8") == md_content


def test_html_report_standalone_and_offline(tmp_path: Path) -> None:
    """HTML report is single-file, zero-dependency, and file:// friendly."""
    report = _create_sample_report()
    html_content = render_html_report(report)

    # Must contain self-contained styles and inline elements
    assert "<!DOCTYPE html>" in html_content
    assert "<style>" in html_content
    assert '<svg class="ring-svg"' in html_content
    assert "92" in html_content  # Score in ring
    assert "Grade A" in html_content
    assert "SEC001" in html_content
    assert "JWT user authentication" in html_content

    # Zero external CDN script or stylesheet dependencies
    assert 'src="http' not in html_content
    assert 'href="http' not in html_content
    assert "googleapis.com" not in html_content
    assert "cdn." not in html_content

    # Write file test
    out_file = tmp_path / "report.html"
    written_path = write_html_report(report, out_file)
    assert written_path.exists()
    assert written_path.stat().st_size > 1000

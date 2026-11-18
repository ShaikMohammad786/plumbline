"""Unit tests for Plumbline data models."""

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


def test_location_and_evidence() -> None:
    loc = Location(path="src/main.py", start_line=10, end_line=12)
    assert loc.path == "src/main.py"
    assert loc.start_line == 10
    assert loc.start_col is None

    ev = Evidence(snippet="val = 1", note="test note")
    assert ev.snippet == "val = 1"
    assert ev.note == "test note"


def test_finding_creation() -> None:
    loc = Location(path="src/app.py", start_line=5, end_line=5)
    ev = Evidence(snippet="password = '123'")
    finding = Finding(
        id="abc123def4567890",
        rule_id="SEC001",
        family="SEC",
        title="Hardcoded secret",
        message="A hardcoded password was found.",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        location=loc,
        evidence=ev,
        fix_hint="Use environment variables.",
        tags=["cwe-798"],
        file_class=FileClass.PROD,
    )
    assert finding.id == "abc123def4567890"
    assert finding.severity == FindingSeverity.CRITICAL
    assert finding.heuristic is False


def test_claim_model() -> None:
    loc = Location(path="README.md", start_line=15, end_line=15)
    claim = Claim(
        id="claim-001",
        text="All routes authenticated",
        source=loc,
        claim_type="authentication",
        verdict=ClaimVerdict.VERIFIED,
    )
    assert claim.verdict == ClaimVerdict.VERIFIED


def test_report_schema_export_and_stability() -> None:
    stats = ScanStats(files=10, lines=500, duration_s=0.25)
    report = Report(
        started_at="2026-11-18T12:00:00Z",
        root="/repo",
        stats=stats,
        score=95,
        grade="A",
    )
    assert report.schema_version == "plumbline.report/1"
    assert report.score == 95

    # Check JSON schema stability
    schema = Report.model_json_schema()
    assert "properties" in schema
    assert "findings" in schema["properties"]
    assert "claims" in schema["properties"]
    assert "stats" in schema["properties"]
    assert "score" in schema["properties"]

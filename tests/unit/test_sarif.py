"""Tests for SARIF 2.1.0 output generation and schema conformity."""

import json
from pathlib import Path

from plumbline.models import (
    Evidence,
    FileClass,
    Finding,
    FindingConfidence,
    FindingSeverity,
    Location,
    Report,
    ScanStats,
)
from plumbline.report.sarif import generate_sarif_dict, render_sarif_report


def test_sarif_210_structure_and_serialization(tmp_path: Path) -> None:
    loc = Location(path="src/api.py", start_line=10, end_line=12)
    ev = Evidence(snippet='requests.get("https://api", verify=False)')
    finding = Finding(
        id="a1b2c3d4e5f67890",
        rule_id="SEC005",
        family="SEC",
        title="TLS certificate verification disabled",
        message="TLS verification explicitly disabled.",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        location=loc,
        evidence=ev,
        fix_hint="Enable verify=True",
        file_class=FileClass.PROD,
        suppressed=False,
    )

    report = Report(
        schema="plumbline.report/1",
        tool_version="0.1.0",
        started_at="2026-11-18T12:00:00Z",
        root=str(tmp_path),
        stats=ScanStats(files=1, lines=12, duration_s=0.05),
        findings=[finding],
        claims=[],
        score=92,
        grade="A",
        score_breakdown={},
        notes=[],
    )

    sarif_dict = generate_sarif_dict(report)

    # 1. Root schema validation
    assert sarif_dict["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert sarif_dict["version"] == "2.1.0"
    assert len(sarif_dict["runs"]) == 1

    # 2. Driver validation
    run = sarif_dict["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "Plumbline"
    assert driver["version"] == "0.1.0"
    assert any(r["id"] == "SEC005" for r in driver["rules"])

    # 3. Results validation
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "SEC005"
    assert res["level"] == "error"  # HIGH severity maps to error
    assert res["partialFingerprints"]["plumbline/v1"] == "a1b2c3d4e5f67890"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 10

    # 4. File rendering
    out_file = tmp_path / "report.sarif"
    render_sarif_report(report, out_file)
    assert out_file.exists()
    loaded = json.loads(out_file.read_text(encoding="utf-8"))
    assert loaded["version"] == "2.1.0"

"""SARIF 2.1.0 report generator conforming to OASIS SARIF standards."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from plumbline.detectors.registry import registry
from plumbline.models import FindingSeverity, Report

SEVERITY_TO_SARIF_LEVEL = {
    FindingSeverity.CRITICAL: "error",
    FindingSeverity.HIGH: "error",
    FindingSeverity.MEDIUM: "warning",
    FindingSeverity.LOW: "note",
    FindingSeverity.INFO: "note",
}


def generate_sarif_dict(report: Report) -> dict[str, Any]:
    """Generate in-memory SARIF 2.1.0 structure from Plumbline Report."""
    rules_data: list[dict[str, Any]] = []

    # Build tool rules metadata from registered rules
    for rule_id, rule_spec in sorted(registry._rules.items()):
        level = SEVERITY_TO_SARIF_LEVEL.get(rule_spec.severity, "warning")
        rule_dict: dict[str, Any] = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": rule_spec.title},
            "fullDescription": {"text": rule_spec.fix_hint[:1000]},
            "defaultConfiguration": {"level": level},
            "properties": {
                "tags": rule_spec.tags,
                "precision": "medium" if rule_spec.heuristic else "very-high",
                "problem": {"severity": rule_spec.severity.value},
            },
        }
        rules_data.append(rule_dict)

    results_data: list[dict[str, Any]] = []
    for f in report.findings:
        level = SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning")
        result: dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": level,
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.location.path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": f.location.start_line,
                            "endLine": f.location.end_line,
                        },
                    }
                }
            ],
            "partialFingerprints": {
                "plumbline/v1": f.id,
            },
        }
        if f.suppressed:
            result["suppressions"] = [{"kind": "inSource", "status": "accepted"}]
        results_data.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Plumbline",
                        "version": report.tool_version,
                        "informationUri": "https://github.com/ShaikMohammad786/plumbline",
                        "rules": rules_data,
                    }
                },
                "results": results_data,
            }
        ],
    }


def render_sarif_report(report: Report, out_path: Optional[Path] = None) -> str:
    """Serialize Report to SARIF 2.1.0 JSON and optionally save to file."""
    sarif_data = generate_sarif_dict(report)
    rendered = json.dumps(sarif_data, indent=2)

    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")

    return rendered


def write_sarif_report(report: Report, out_path: Optional[Path] = None) -> Path:
    """Serialize Report to SARIF 2.1.0 JSON and save directly to file."""
    if out_path is None:
        out_path = Path("report.sarif")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    render_sarif_report(report, out_path)
    return out_path

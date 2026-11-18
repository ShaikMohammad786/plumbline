"""Inline comment suppressions (plumbline:ignore[RULE_ID] reason)."""

from __future__ import annotations

import re

from plumbline.detectors.context import ScanContext
from plumbline.fusion.fingerprint import compute_fingerprint
from plumbline.models import (
    Evidence,
    Finding,
    FindingConfidence,
    FindingSeverity,
    Location,
)

IGNORE_PATTERN = re.compile(r"""plumbline:ignore\[([A-Za-z0-9_,\s]+)\](?:\s+(.*))?""")


def apply_suppressions(findings: list[Finding], context: ScanContext) -> list[Finding]:
    """Apply inline suppressions and flag unreasoned ignore comments (GAP009)."""
    suppression_map: dict[str, dict[int, list[tuple[str, str]]]] = {}
    gap009_findings: list[Finding] = []

    # 1. Parse all ignore comments across files
    for f in context.files:
        if f.path.endswith((".html", ".json", ".sarif", ".map")):
            continue
        lines = context.get_lines(f.path)
        file_suppressions: dict[int, list[tuple[str, str]]] = {}

        for line_no, line in enumerate(lines, start=1):
            m = IGNORE_PATTERN.search(line)
            if m:
                raw_rules = m.group(1)
                reason = (m.group(2) or "").strip()
                rules = [r.strip() for r in raw_rules.split(",") if r.strip()]

                # Reason is mandatory! An ignore without a reason is GAP009
                if not reason:
                    snippet = line[:500].strip()
                    fp = compute_fingerprint("GAP009", snippet, f.path)
                    gap009_findings.append(
                        Finding(
                            id=fp,
                            rule_id="GAP009",
                            family="GAP",
                            title="Suppression without reason",
                            message="A plumbline:ignore comment was found with no written reason.",
                            severity=FindingSeverity.LOW,
                            confidence=FindingConfidence.HIGH,
                            location=Location(path=f.path, start_line=line_no, end_line=line_no),
                            evidence=Evidence(snippet=snippet),
                            fix_hint="Add a mandatory explanation why this finding is ignored.",
                            tags=["hygiene"],
                            file_class=f.file_class,
                        )
                    )

                for r in rules:
                    file_suppressions.setdefault(line_no, []).append((r, reason))

        if file_suppressions:
            suppression_map[f.path] = file_suppressions

    # 2. Check each finding against suppressions on line or line above
    processed: list[Finding] = []
    for finding in findings:
        path = finding.location.path
        start_line = finding.location.start_line
        is_suppressed = False

        if path in suppression_map:
            file_sups = suppression_map[path]
            # Check line above, exact line, or immediate inner line (for single-line/handler blocks)
            for check_line in (start_line - 1, start_line, start_line + 1):
                if check_line in file_sups:
                    for rule_id, reason in file_sups[check_line]:
                        if (rule_id == finding.rule_id or rule_id == "*") and reason:
                            is_suppressed = True
                            break
                if is_suppressed:
                    break

        if is_suppressed:
            finding.suppressed = True

        processed.append(finding)

    processed.extend(gap009_findings)
    return processed

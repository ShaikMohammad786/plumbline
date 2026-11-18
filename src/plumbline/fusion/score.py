"""Repo Truth Score calculation and breakdown."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Optional

from plumbline.models import (
    Claim,
    ClaimVerdict,
    FileClass,
    Finding,
    FindingConfidence,
    FindingSeverity,
)

SEVERITY_WEIGHTS: dict[FindingSeverity, float] = {
    FindingSeverity.CRITICAL: 20.0,
    FindingSeverity.HIGH: 8.0,
    FindingSeverity.MEDIUM: 3.0,
    FindingSeverity.LOW: 1.0,
    FindingSeverity.INFO: 0.0,
}

CONFIDENCE_MULTS: dict[FindingConfidence, float] = {
    FindingConfidence.HIGH: 1.0,
    FindingConfidence.MEDIUM: 0.6,
    FindingConfidence.LOW: 0.3,
}

PATH_MULTS: dict[FileClass, float] = {
    FileClass.PROD: 1.0,
    FileClass.TEST: 0.2,
    FileClass.EXAMPLE: 0.3,
    FileClass.DOCS: 0.3,
    FileClass.GENERATED: 0.1,
    FileClass.VENDOR: 0.0,
}

CLAIM_PENALTIES: dict[ClaimVerdict, float] = {
    ClaimVerdict.CONTRADICTED: 10.0,
    ClaimVerdict.UNSUPPORTED: 5.0,
    ClaimVerdict.PARTIAL: 2.0,
    ClaimVerdict.VERIFIED: 0.0,
    ClaimVerdict.UNCHECKED: 0.0,
}


def compute_repo_truth_score(
    findings: list[Finding],
    claims: Optional[list[Claim]] = None,
) -> tuple[int, str, dict[str, Any]]:
    """Compute 0-100 Repo Truth Score, Letter Grade, and score breakdown."""
    active_findings = [f for f in findings if not f.suppressed and not f.baselined]

    # 1. Group active findings by rule_id
    rule_groups: dict[str, list[float]] = {}
    for f in active_findings:
        sev_w = SEVERITY_WEIGHTS.get(f.severity, 1.0)
        conf_m = CONFIDENCE_MULTS.get(f.confidence, 1.0)
        path_m = PATH_MULTS.get(f.file_class, 1.0)
        penalty = sev_w * conf_m * path_m
        rule_groups.setdefault(f.rule_id, []).append(penalty)

    # 2. Rule penalty formula: base * (1 + 0.5 * ln(n))
    finding_penalty_total = 0.0
    rule_breakdown: dict[str, float] = {}

    for rule_id, penalties in rule_groups.items():
        base = max(penalties)
        n = len(penalties)
        rule_pen = base * (1.0 + 0.5 * math.log(n)) if n > 0 else 0.0
        rule_breakdown[rule_id] = round(rule_pen, 2)
        finding_penalty_total += rule_pen

    # 3. Claims penalties
    claims_penalty_total = 0.0
    claim_breakdown: dict[str, float] = {}

    if claims:
        for c in claims:
            pen = CLAIM_PENALTIES.get(c.verdict, 0.0)
            if pen > 0:
                claim_breakdown[c.id] = pen
                claims_penalty_total += pen

    total_penalty = finding_penalty_total + claims_penalty_total
    score = max(0, 100 - round(total_penalty))

    # Grade thresholds: A >= 90, B >= 80, C >= 70, D >= 60, else F
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    breakdown = {
        "finding_penalties": round(finding_penalty_total, 2),
        "claim_penalties": round(claims_penalty_total, 2),
        "total_penalty": round(total_penalty, 2),
        "rules": rule_breakdown,
        "claims": claim_breakdown,
    }

    return score, grade, breakdown


def write_scoring_docs(out_path: Optional[Path] = None) -> None:
    """Write docs/SCORING.md explaining the scoring formula."""
    target = out_path or Path("docs/SCORING.md")
    content = """# Plumbline Repo Truth Score Documentation

Plumbline computes an objective, normalized **0–100 Repo Truth Score** and assigns a letter grade (A, B, C, D, or F).

## Penalty Calculation

For each finding:
```
finding_penalty = severity_weight * confidence_mult * path_mult
```

### Weights & Multipliers

#### Severity Weight
- **Critical**: 20.0
- **High**: 8.0
- **Medium**: 3.0
- **Low**: 1.0
- **Info**: 0.0

#### Confidence Multiplier
- **High**: 1.0
- **Medium**: 0.6
- **Low**: 0.3

#### Path Classification Multiplier
- **Production (`prod`)**: 1.0
- **Test (`test`)**: 0.2
- **Example / Docs (`example`, `docs`)**: 0.3
- **Generated (`generated`)**: 0.1
- **Vendor (`vendor`)**: 0.0

---

## Logarithmic Rule Dampening

To prevent a single noisy rule from disproportionately destroying the repository score, multiple findings of the same rule scale logarithmically:
```
rule_penalty = base * (1 + 0.5 * ln(n))
```
where `base` is the largest single finding penalty for that rule, and `n` is the count of findings for that rule.

---

## Claim Ledger Penalties

- **CONTRADICTED**: 10.0 points
- **UNSUPPORTED**: 5.0 points
- **PARTIAL**: 2.0 points
- **VERIFIED**: 0.0 points

---

## Final Score & Grading Scale

```
score = max(0, 100 - round(total_penalty))
```

- **A**: Score >= 90 (Excellent truth fidelity)
- **B**: Score >= 80 (Good code health, minor loose ends)
- **C**: Score >= 70 (Moderate concerns or missing controls)
- **D**: Score >= 60 (Significant gaps or security issues)
- **F**: Score < 60 (Critical vulnerabilities, AI slop, or contradicted claims)
"""
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")

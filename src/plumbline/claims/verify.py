"""Rule-based verification of extracted claims against Universal Code Model facts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from plumbline.claims.extract import load_taxonomy
from plumbline.models import Claim, ClaimVerdict, Finding, FindingConfidence

if TYPE_CHECKING:
    from plumbline.detectors.context import ScanContext


def verify_claim(
    claim: Claim,
    context: ScanContext,
    findings: Optional[list[Finding]] = None,
) -> Claim:
    """Verify a single claim against repo facts and active findings."""
    taxonomy = load_taxonomy()
    cat_rules = taxonomy.get(claim.claim_type, {})
    if not cat_rules:
        claim.verdict = ClaimVerdict.UNSUPPORTED
        return claim

    positive_cfg: dict[str, Any] = cat_rules.get("positive", {})
    counter_cfg: dict[str, Any] = cat_rules.get("counter_evidence", {})

    evidence_items: list[dict[str, Any]] = []
    counter_items: list[dict[str, Any]] = []

    active_rule_ids = {f.rule_id for f in (findings or []) if not f.suppressed and not f.baselined}

    # 1. Check counter-evidence rules
    for bad_rule in counter_cfg.get("rules", []):
        if bad_rule in active_rule_ids:
            matching_findings = [f for f in (findings or []) if f.rule_id == bad_rule]
            for mf in matching_findings[:2]:
                counter_items.append(
                    {
                        "path": mf.location.path,
                        "line": mf.location.start_line,
                        "note": f"Contradicted by active issue {mf.rule_id}: {mf.title}",
                    }
                )

    # 2. Check positive evidence
    # Files
    required_files = positive_cfg.get("files", [])
    for rf in required_files:
        for f in context.files:
            if rf in f.path:
                evidence_items.append(
                    {"path": f.path, "line": 1, "note": f"Found required file/pattern '{rf}'"}
                )
                break

    # Imports, calls, routes, guards
    required_imports = positive_cfg.get("imports", [])
    required_calls = positive_cfg.get("calls", [])
    routes_present = positive_cfg.get("routes_present", False)
    guard_keywords = positive_cfg.get("guard_keywords", [])

    imports_found = 0
    calls_found = 0

    for path, facts in context.all_facts().items():
        if not context.is_prod(path) and claim.claim_type != "tests":
            continue

        # Check imports
        if required_imports:
            for imp in facts.imports:
                for req_imp in required_imports:
                    if req_imp in imp.module.lower():
                        imports_found += 1
                        evidence_items.append(
                            {
                                "path": path,
                                "line": imp.line,
                                "note": f"Imported module '{imp.module}'",
                            }
                        )
                        break

        # Check calls
        if required_calls:
            for call in facts.call_sites:
                for req_call in required_calls:
                    if req_call.lower() in call.callee.lower():
                        calls_found += 1
                        evidence_items.append(
                            {
                                "path": path,
                                "line": call.line,
                                "note": f"Invoked function '{call.callee}'",
                            }
                        )
                        break

        # Check routes
        if routes_present and facts.routes:
            for r in facts.routes[:2]:
                evidence_items.append(
                    {
                        "path": path,
                        "line": r.line,
                        "note": f"Registered route handler '{r.method} {r.path}'",
                    }
                )

        # Check guards
        if guard_keywords:
            lines = context.get_lines(path)
            for line_no, raw in enumerate(lines, start=1):
                lower = raw.lower()
                for gk in guard_keywords:
                    if gk in lower and any(
                        sym in lower for sym in ("def ", "class ", "@", "function", "const")
                    ):
                        evidence_items.append(
                            {
                                "path": path,
                                "line": line_no,
                                "note": f"Guard keyword '{gk}' observed in code",
                            }
                        )
                        break

    # Determine verdict
    if counter_items:
        claim.verdict = ClaimVerdict.CONTRADICTED
        claim.evidence = counter_items + evidence_items[:2]
        claim.confidence = FindingConfidence.HIGH
    elif evidence_items:
        # Check if evidence is full or partial
        has_imports = imports_found > 0 or not required_imports
        has_calls = calls_found > 0 or not required_calls
        if has_imports and has_calls:
            claim.verdict = ClaimVerdict.VERIFIED
            claim.evidence = evidence_items[:5]
        else:
            claim.verdict = ClaimVerdict.PARTIAL
            claim.evidence = evidence_items[:3]
    else:
        claim.verdict = ClaimVerdict.UNSUPPORTED
        claim.evidence = [
            {
                "path": claim.source.path,
                "line": claim.source.start_line,
                "note": "No matching code evidence found in repository",
            }
        ]

    return claim


def verify_all_claims(
    claims: list[Claim],
    context: ScanContext,
    findings: Optional[list[Finding]] = None,
) -> list[Claim]:
    """Verify all extracted claims against code model."""
    return [verify_claim(c, context, findings) for c in claims]

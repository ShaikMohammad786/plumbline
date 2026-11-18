"""Claim Ledger detector rules (CLM001-CLM004)."""

from __future__ import annotations

import re

from plumbline.claims.extract import extract_claims
from plumbline.claims.verify import verify_all_claims
from plumbline.detectors.base import RuleSpec
from plumbline.detectors.context import ScanContext
from plumbline.detectors.registry import rule
from plumbline.fusion.fingerprint import compute_fingerprint
from plumbline.models import (
    Claim,
    ClaimVerdict,
    Evidence,
    FileClass,
    Finding,
    FindingConfidence,
    FindingSeverity,
    Location,
)

# CLM001: Claim with no code evidence
CLM001_SPEC = RuleSpec(
    id="CLM001",
    title="Claim asserted in documentation without code evidence",
    family="CLM",
    severity=FindingSeverity.HIGH,
    confidence=FindingConfidence.HIGH,
    tags=["documentation", "claim-vs-reality"],
    bad="README claims: 'FastAPI service with JWT authentication', but zero JWT imports or auth logic exists.",
    good="Implement the claimed capability or remove the claim from documentation.",
    fix_hint="Implement the claimed feature or remove the claim from documentation.",
)

# CLM002: Claim contradicted by code
CLM002_SPEC = RuleSpec(
    id="CLM002",
    title="Documentation claim contradicted by code evidence",
    family="CLM",
    severity=FindingSeverity.HIGH,
    confidence=FindingConfidence.HIGH,
    tags=["documentation", "contradiction", "cwe-398"],
    bad="README claims: 'All network requests use strict TLS verification', but code sets verify=False.",
    good="Align code implementation with documented security commitments.",
    fix_hint="Remediate the contradictory vulnerability or align documentation with reality.",
)

# CLM003: Claim partly implemented
CLM003_SPEC = RuleSpec(
    id="CLM003",
    title="Claim only partly implemented with missing controls",
    family="CLM",
    severity=FindingSeverity.MEDIUM,
    confidence=FindingConfidence.MEDIUM,
    tags=["documentation", "incomplete-work"],
    bad="README claims: 'Protected endpoints require RBAC permissions', but permission guards are not attached.",
    good="Fully wire the required middleware and endpoint controls.",
    fix_hint="Complete implementation of the required guards, endpoints, and middleware.",
)

# CLM004: Fake implementation returning literals
CLM004_SPEC = RuleSpec(
    id="CLM004",
    title="Fake implementation: non-test function ignores parameters and returns literals",
    family="CLM",
    severity=FindingSeverity.HIGH,
    confidence=FindingConfidence.HIGH,
    tags=["slop", "fake-implementation", "cwe-398"],
    bad="def verify_token(token):\n    return True",
    good="def verify_token(token):\n    return jwt.decode(token, SECRET, algorithms=['HS256'])",
    fix_hint="Implement authentic validation logic instead of returning hardcoded truthy or literal values.",
)


def _get_or_verify_claims(context: ScanContext) -> list[Claim]:
    """Retrieve or compute verified claims for the current scan context."""
    if hasattr(context, "_claims_cache") and context._claims_cache is not None:
        return context._claims_cache  # type: ignore[no-any-return]
    raw_claims = extract_claims(context)
    verified = verify_all_claims(raw_claims, context)
    context._claims_cache = verified  # type: ignore[attr-defined]
    return verified


@rule(CLM001_SPEC)
def detect_clm001(context: ScanContext) -> list[Finding]:
    """Flag unsupported documentation claims."""
    findings: list[Finding] = []
    claims = _get_or_verify_claims(context)

    for claim in claims:
        if claim.verdict == ClaimVerdict.UNSUPPORTED:
            fp = compute_fingerprint("CLM001", claim.text, claim.source.path)
            findings.append(
                Finding(
                    id=fp,
                    rule_id="CLM001",
                    family="CLM",
                    title=CLM001_SPEC.title,
                    message=f"Documentation claims '{claim.claim_type}' capability, but zero code evidence exists.",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                    location=claim.source,
                    evidence=Evidence(snippet=claim.text),
                    fix_hint=CLM001_SPEC.fix_hint,
                    tags=CLM001_SPEC.tags,
                    file_class=FileClass.DOCS,
                )
            )
    return findings


@rule(CLM002_SPEC)
def detect_clm002(context: ScanContext) -> list[Finding]:
    """Flag claims contradicted by code or active security vulnerabilities."""
    findings: list[Finding] = []
    claims = _get_or_verify_claims(context)

    for claim in claims:
        if claim.verdict == ClaimVerdict.CONTRADICTED:
            fp = compute_fingerprint("CLM002", claim.text, claim.source.path)
            findings.append(
                Finding(
                    id=fp,
                    rule_id="CLM002",
                    family="CLM",
                    title=CLM002_SPEC.title,
                    message=f"Documentation claims '{claim.claim_type}', but code evidence directly contradicts it.",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                    location=claim.source,
                    evidence=Evidence(snippet=claim.text),
                    fix_hint=CLM002_SPEC.fix_hint,
                    tags=CLM002_SPEC.tags,
                    file_class=FileClass.DOCS,
                )
            )
    return findings


@rule(CLM003_SPEC)
def detect_clm003(context: ScanContext) -> list[Finding]:
    """Flag partly implemented claims."""
    findings: list[Finding] = []
    claims = _get_or_verify_claims(context)

    for claim in claims:
        if claim.verdict == ClaimVerdict.PARTIAL:
            fp = compute_fingerprint("CLM003", claim.text, claim.source.path)
            findings.append(
                Finding(
                    id=fp,
                    rule_id="CLM003",
                    family="CLM",
                    title=CLM003_SPEC.title,
                    message=f"Documentation claims '{claim.claim_type}', but code only implements partial indicators.",
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.MEDIUM,
                    location=claim.source,
                    evidence=Evidence(snippet=claim.text),
                    fix_hint=CLM003_SPEC.fix_hint,
                    tags=CLM003_SPEC.tags,
                    file_class=FileClass.DOCS,
                )
            )
    return findings


FAKE_RETURN_RE = re.compile(
    r"""^\s*return\s+(True|False|None|""|''|\[\]|\{\}|0|1|OK|SUCCESS)\s*;?$""",
    re.IGNORECASE,
)

FAKE_NAME_KEYWORDS = {
    "verify",
    "validate",
    "check",
    "auth",
    "is_valid",
    "has_permission",
    "encrypt",
    "decrypt",
    "sanitize",
    "clean",
}


@rule(CLM004_SPEC)
def detect_clm004(context: ScanContext) -> list[Finding]:
    """Flag fake implementations where functions ignore arguments and return constant literals."""
    findings: list[Finding] = []
    for f in context.files:
        if not context.is_prod(f.path) or "detectors" in f.path:
            continue
        facts = context.get_facts(f.path)
        if not facts:
            continue
        lines = context.get_lines(f.path)

        for sym in facts.symbols:
            if sym.kind not in ("function", "method"):
                continue
            if not sym.params or len(sym.params) == 0:
                continue

            name_lower = sym.name.lower()
            if not any(k in name_lower for k in FAKE_NAME_KEYWORDS):
                continue

            body_lines = [
                line.strip()
                for line in lines[sym.start_line : sym.end_line]
                if line.strip()
                and not line.strip().startswith(("#", "//", "/*", "*", '"""', "'''"))
            ]

            if len(body_lines) == 1 and FAKE_RETURN_RE.match(body_lines[0]):
                snippet = f"{sym.name}({', '.join(sym.params)}): {body_lines[0]}"
                fp = compute_fingerprint("CLM004", snippet, f.path)
                findings.append(
                    Finding(
                        id=fp,
                        rule_id="CLM004",
                        family="CLM",
                        title=CLM004_SPEC.title,
                        message=f"Function '{sym.name}' takes parameters but immediately returns hardcoded literal without verification.",
                        severity=FindingSeverity.HIGH,
                        confidence=FindingConfidence.HIGH,
                        location=Location(
                            path=f.path, start_line=sym.start_line, end_line=sym.end_line
                        ),
                        evidence=Evidence(snippet=snippet),
                        fix_hint=CLM004_SPEC.fix_hint,
                        tags=CLM004_SPEC.tags,
                        file_class=f.file_class,
                    )
                )

    return findings

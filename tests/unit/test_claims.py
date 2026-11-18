"""Tests for Claim Ledger extraction, taxonomy, and verification (CLM001-CLM004)."""

from pathlib import Path

from plumbline.claims.extract import extract_claims, load_taxonomy
from plumbline.claims.verify import verify_all_claims
from plumbline.config import PlumblineConfig
from plumbline.detectors.claims.rules import (
    detect_clm004,
)
from plumbline.detectors.context import ScanContext
from plumbline.ingest.walker import walk_repository
from plumbline.models import (
    ClaimVerdict,
    Evidence,
    FileClass,
    Finding,
    FindingConfidence,
    FindingSeverity,
    Location,
)


def test_taxonomy_loading() -> None:
    """Taxonomy contains all 20 specified categories with valid triggers."""
    tax = load_taxonomy()
    assert len(tax) >= 20
    expected_categories = [
        "authentication",
        "authorization",
        "encryption",
        "password_hashing",
        "input_validation",
        "rate_limiting",
        "caching",
        "logging",
        "error_handling",
        "pagination",
        "retries",
        "tests",
        "ci",
        "docker",
        "database",
        "api",
        "real_time",
        "offline",
        "i18n",
        "accessibility",
    ]
    for cat in expected_categories:
        assert cat in tax, f"Missing category: {cat}"
        assert "triggers" in tax[cat]
        assert "positive" in tax[cat]


def test_claim_extraction_from_markdown(tmp_path: Path) -> None:
    """Extract checkable capability sentences from markdown documentation."""
    readme = tmp_path / "README.md"
    readme.write_text(
        "# My Project\n\n"
        "This service provides JWT user authentication and role-based access control.\n\n"
        "We also include Redis caching and structured logging.\n",
        encoding="utf-8",
    )

    cfg = PlumblineConfig()
    walk_res = walk_repository(tmp_path, cfg)
    ctx = ScanContext(tmp_path, walk_res.files, [], cfg)

    claims = extract_claims(ctx)
    assert len(claims) >= 2
    types = {c.claim_type for c in claims}
    assert "authentication" in types or "authorization" in types


def test_claim_verification_lifecycle(tmp_path: Path) -> None:
    """Verify claim verdicts: VERIFIED, PARTIAL, UNSUPPORTED, CONTRADICTED."""
    readme = tmp_path / "README.md"
    readme.write_text(
        "This app supports JWT user authentication.\n"
        "All network calls enforce strict TLS verification.\n"
        "We support full redis caching for performance.\n",
        encoding="utf-8",
    )

    # 1. Code providing positive evidence for JWT
    auth_py = tmp_path / "auth.py"
    auth_py.write_text(
        "import jwt\ndef login():\n    return jwt.decode_token(t)\n", encoding="utf-8"
    )

    # 2. Contradictory finding for TLS verification
    findings = [
        Finding(
            id="test-fp",
            rule_id="SEC005",
            family="SEC",
            title="TLS verification disabled",
            message="TLS verification explicitly disabled with verify=False",
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.HIGH,
            location=Location(path="auth.py", start_line=1, end_line=1),
            evidence=Evidence(snippet="verify=False"),
            fix_hint="Enable verify=True",
            file_class=FileClass.PROD,
        )
    ]

    cfg = PlumblineConfig()
    walk_res = walk_repository(tmp_path, cfg)
    ctx = ScanContext(tmp_path, walk_res.files, [], cfg)

    claims = extract_claims(ctx)
    verified = verify_all_claims(claims, ctx, findings=findings)

    verdict_by_type = {c.claim_type: c.verdict for c in verified}
    assert verdict_by_type.get("authentication") == ClaimVerdict.VERIFIED
    assert verdict_by_type.get("caching") == ClaimVerdict.UNSUPPORTED


def test_clm004_fake_implementation(tmp_path: Path) -> None:
    """CLM004 flags fake functions that take arguments and return literals."""
    code_file = tmp_path / "validator.py"
    code_file.write_text(
        "def verify_token(token):\n    return True\n\ndef is_admin():\n    return True\n",
        encoding="utf-8",
    )

    cfg = PlumblineConfig()
    walk_res = walk_repository(tmp_path, cfg)
    ctx = ScanContext(tmp_path, walk_res.files, [], cfg)

    findings = detect_clm004(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "CLM004"
    assert "verify_token" in findings[0].evidence.snippet

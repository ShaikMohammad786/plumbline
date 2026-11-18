"""GAP family detectors (GAP001 - GAP009): Loose ends and unfinished work."""

from __future__ import annotations

import os
import re
from pathlib import PurePath

from plumbline.detectors.base import RuleSpec
from plumbline.detectors.context import ScanContext
from plumbline.detectors.registry import rule
from plumbline.fusion.fingerprint import compute_fingerprint
from plumbline.models import (
    Evidence,
    FileClass,
    Finding,
    FindingConfidence,
    FindingSeverity,
    Location,
)

# GAP001: TODO/FIXME/HACK/XXX
GAP001_SPEC = RuleSpec(
    id="GAP001",
    title="Unresolved TODO, FIXME, HACK, or XXX",
    family="GAP",
    severity=FindingSeverity.MEDIUM,
    confidence=FindingConfidence.HIGH,
    tags=["cwe-546", "technical-debt"],
    bad="// TODO: implement rate limiting",
    good="// Rate limiting implemented via Redis token bucket",
    fix_hint="Resolve the unfinished work or document the tracking issue.",
)

SECURITY_KEYWORDS = {
    "auth",
    "password",
    "token",
    "secret",
    "verify",
    "validate",
    "permission",
    "csrf",
    "encrypt",
}
TODO_RE = re.compile(r"\b(TODO|FIXME|HACK|XXX)\b")


@rule(GAP001_SPEC)
def detect_gap001(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in context.files:
        if f.file_class in (FileClass.DOCS, FileClass.VENDOR, FileClass.GENERATED):
            continue
        lines = context.get_lines(f.path)
        for line_no, raw in enumerate(lines, start=1):
            line = raw.strip()
            if not line.startswith(("#", "//", "/*", "*", "--")):
                continue
            if line.startswith(("# GAP", "// GAP", "/* GAP", "* GAP")):
                continue
            if "detectors" in f.path and any(
                k in line for k in ("RuleSpec", "bad=", "good=", "fix_hint=")
            ):
                continue

            m = TODO_RE.search(line)
            if m:
                # Proximity check: within 5 lines of security keywords
                start_w = max(0, line_no - 6)
                end_w = min(len(lines), line_no + 5)
                window_text = " ".join(lines[start_w:end_w]).lower()

                has_security = any(sec in window_text for sec in SECURITY_KEYWORDS)
                severity = FindingSeverity.HIGH if has_security else FindingSeverity.MEDIUM
                msg = (
                    f"Unresolved {m.group(1)} in security-sensitive context."
                    if has_security
                    else f"Unresolved {m.group(1)} marker."
                )

                fp = compute_fingerprint("GAP001", line, f.path)
                findings.append(
                    Finding(
                        id=fp,
                        rule_id="GAP001",
                        family="GAP",
                        title=GAP001_SPEC.title,
                        message=msg,
                        severity=severity,
                        confidence=FindingConfidence.HIGH,
                        location=Location(path=f.path, start_line=line_no, end_line=line_no),
                        evidence=Evidence(snippet=line),
                        fix_hint=GAP001_SPEC.fix_hint,
                        tags=GAP001_SPEC.tags,
                        file_class=f.file_class,
                    )
                )
    return findings


# GAP002: Stub body
GAP002_SPEC = RuleSpec(
    id="GAP002",
    title="Unimplemented stub function or method",
    family="GAP",
    severity=FindingSeverity.MEDIUM,
    confidence=FindingConfidence.HIGH,
    tags=["cwe-546"],
    bad="def authenticate(user, password):\n    pass",
    good="def authenticate(user, password):\n    return verify_hash(password, user.pwd_hash)",
    fix_hint="Provide a complete implementation instead of a dummy stub.",
)

STUB_NAME_KEYWORDS = {
    "auth",
    "verify",
    "validate",
    "check",
    "is_",
    "has_",
    "can_",
    "encrypt",
    "decrypt",
    "hash",
    "sanitize",
}


@rule(GAP002_SPEC)
def detect_gap002(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in context.files:
        if f.file_class in (FileClass.DOCS, FileClass.VENDOR, FileClass.GENERATED):
            continue
        lines = context.get_lines(f.path)
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if "detectors" in f.path and any(k in stripped for k in ("bad=", "good=", "RuleSpec(")):
                continue
            # Match function definition
            if (
                stripped.startswith("def ")
                or stripped.startswith("function ")
                or stripped.startswith("func ")
            ):
                # Look for first non-comment line in body
                first_body_line = None
                for offset in range(1, 6):
                    if idx + offset < len(lines):
                        cand = lines[idx + offset].strip()
                        if cand and not cand.startswith(("#", "//", "/*", "*")):
                            first_body_line = cand
                            break

                if first_body_line:
                    next_line = first_body_line
                    # Check pass, ellipsis, or NotImplementedError
                    is_stub = (
                        next_line in ("pass", "...", '"""..."""', "'''...'''")
                        or "raise NotImplementedError" in next_line
                        or 'panic("not implemented")' in next_line
                        or "throw new Error" in next_line
                        and ("not implemented" in next_line.lower() or "todo" in next_line.lower())
                    )

                    # Check constant return on security name
                    fn_name_match = re.search(r"(?:def|function|func)\s+([a-zA-Z0-9_]+)", stripped)
                    fn_name = fn_name_match.group(1).lower() if fn_name_match else ""
                    has_sec_name = any(k in fn_name for k in STUB_NAME_KEYWORDS)

                    if not is_stub and has_sec_name:
                        if next_line in (
                            "return None",
                            "return True",
                            "return False",
                            "return true",
                            "return false",
                            "return nil",
                            "return 0",
                            'return ""',
                            "return []",
                            "return {}",
                        ):
                            is_stub = True

                    # Filter out abstract methods and interfaces
                    prev_slice = lines[max(0, idx - 2) : idx + 1]
                    is_abstract = any(
                        "abstractmethod" in line_str
                        or "protocol" in line_str.lower()
                        or "@overload" in line_str
                        for line_str in prev_slice
                    )

                    if is_stub and not is_abstract:
                        severity = FindingSeverity.HIGH if has_sec_name else FindingSeverity.MEDIUM
                        fp = compute_fingerprint("GAP002", stripped + "\n" + next_line, f.path)
                        findings.append(
                            Finding(
                                id=fp,
                                rule_id="GAP002",
                                family="GAP",
                                title=GAP002_SPEC.title,
                                message=f"Stub implementation for function '{fn_name}'.",
                                severity=severity,
                                confidence=FindingConfidence.HIGH,
                                location=Location(
                                    path=f.path, start_line=idx + 1, end_line=idx + 2
                                ),
                                evidence=Evidence(snippet=f"{stripped}\n{next_line}"),
                                fix_hint=GAP002_SPEC.fix_hint,
                                tags=GAP002_SPEC.tags,
                                file_class=f.file_class,
                            )
                        )
    return findings


# GAP003: Skipped or unasserted tests
GAP003_SPEC = RuleSpec(
    id="GAP003",
    title="Skipped, empty, or unasserted test",
    family="GAP",
    severity=FindingSeverity.MEDIUM,
    confidence=FindingConfidence.HIGH,
    tags=["quality", "tests"],
    bad="@pytest.mark.skip\ndef test_payments(): pass",
    good="def test_payments():\n    assert charge() == 200",
    fix_hint="Un-skip the test or add verifiable assertions.",
)


@rule(GAP003_SPEC)
def detect_gap003(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in context.files:
        if f.file_class != FileClass.TEST:
            continue
        lines = context.get_lines(f.path)
        for line_no, raw in enumerate(lines, start=1):
            line = raw.strip()
            # Skipped annotations
            if (
                "@pytest.mark.skip" in line
                or "@unittest.skip" in line
                or "xit(" in line
                or "it.skip(" in line
                or "test.skip(" in line
                or "describe.skip(" in line
                or "t.Skip(" in line
                or "@Disabled" in line
            ):
                fp = compute_fingerprint("GAP003", line, f.path)
                findings.append(
                    Finding(
                        id=fp,
                        rule_id="GAP003",
                        family="GAP",
                        title=GAP003_SPEC.title,
                        message="Test is explicitly skipped or disabled.",
                        severity=FindingSeverity.MEDIUM,
                        confidence=FindingConfidence.HIGH,
                        location=Location(path=f.path, start_line=line_no, end_line=line_no),
                        evidence=Evidence(snippet=line),
                        fix_hint=GAP003_SPEC.fix_hint,
                        tags=GAP003_SPEC.tags,
                        file_class=f.file_class,
                    )
                )
    return findings


# GAP004: Untested source module (Heuristic)
GAP004_SPEC = RuleSpec(
    id="GAP004",
    title="Untested production module",
    family="GAP",
    severity=FindingSeverity.LOW,
    confidence=FindingConfidence.MEDIUM,
    heuristic=True,
    tags=["tests", "coverage"],
    bad="# File: src/payments.py with no tests/test_payments.py",
    good="# File: src/payments.py with tests/test_payments.py",
    fix_hint="Add automated test suite covering this module.",
)


@rule(GAP004_SPEC)
def detect_gap004(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    test_paths = {f.path for f in context.files if f.file_class.value == "test"}
    test_stems = {
        PurePath(p)
        .stem.replace("test_", "")
        .replace("_test", "")
        .replace(".test", "")
        .replace(".spec", "")
        for p in test_paths
    }

    for f in context.files:
        if not context.is_prod(f.path) or f.language not in (
            "python",
            "javascript",
            "typescript",
            "go",
        ):
            continue
        stem = PurePath(f.path).stem
        if stem.startswith("__") or stem in ("cli", "main", "config", "models"):
            continue

        facts = context.get_facts(f.path)
        if facts and facts.symbols:
            if stem not in test_stems:
                fp = compute_fingerprint("GAP004", f.path, f.path)
                findings.append(
                    Finding(
                        id=fp,
                        rule_id="GAP004",
                        family="GAP",
                        title=GAP004_SPEC.title,
                        message=f"(Heuristic) Production module '{f.path}' has no corresponding test module.",
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.MEDIUM,
                        heuristic=True,
                        location=Location(path=f.path, start_line=1, end_line=1),
                        evidence=Evidence(snippet=f"Module: {f.path}"),
                        fix_hint=GAP004_SPEC.fix_hint,
                        tags=GAP004_SPEC.tags,
                        file_class=f.file_class,
                    )
                )
    return findings


# GAP005: Unregistered handler or unreferenced export
GAP005_SPEC = RuleSpec(
    id="GAP005",
    title="Unregistered handler or unreferenced export",
    family="GAP",
    severity=FindingSeverity.MEDIUM,
    confidence=FindingConfidence.MEDIUM,
    heuristic=True,
    tags=["dead-code", "wiring"],
    bad="def handle_payment_webhook(request): ... # Never mounted on any route",
    good="app.post('/webhook', handle_payment_webhook)",
    fix_hint="Mount handler to an application route or remove unreferenced code.",
)


@rule(GAP005_SPEC)
def detect_gap005(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in context.files:
        if not context.is_prod(f.path):
            continue
        facts = context.get_facts(f.path)
        if not facts:
            continue
        for sym in facts.symbols:
            name_lower = sym.name.lower()
            if (
                name_lower.startswith("handle") or name_lower.endswith("handler")
            ) and not name_lower.startswith("handle_safe"):
                refs = context.find_references(sym.name)
                # If only self reference or 0 references
                if len(refs) <= 1:
                    fp = compute_fingerprint("GAP005", sym.name, f.path)
                    findings.append(
                        Finding(
                            id=fp,
                            rule_id="GAP005",
                            family="GAP",
                            title=GAP005_SPEC.title,
                            message=f"(Heuristic) Handler '{sym.name}' appears to never be registered or called.",
                            severity=FindingSeverity.MEDIUM,
                            confidence=FindingConfidence.MEDIUM,
                            heuristic=True,
                            location=Location(
                                path=f.path, start_line=sym.start_line, end_line=sym.end_line
                            ),
                            evidence=Evidence(snippet=f"def {sym.name}(...)"),
                            fix_hint=GAP005_SPEC.fix_hint,
                            tags=GAP005_SPEC.tags,
                            file_class=f.file_class,
                        )
                    )
    return findings


# GAP006: Undocumented environment variable
GAP006_SPEC = RuleSpec(
    id="GAP006",
    title="Undocumented environment variable",
    family="GAP",
    severity=FindingSeverity.LOW,
    confidence=FindingConfidence.HIGH,
    tags=["documentation", "configuration"],
    bad="api_key = os.environ['STRIPE_KEY'] # Missing from README and .env.example",
    good="# Documented in .env.example: STRIPE_KEY=your_key_here",
    fix_hint="Document this environment variable in .env.example and README.md.",
)

STANDARD_ENVS = {"PATH", "HOME", "CI", "NODE_ENV", "PWD", "USER", "PORT", "HOST"}


@rule(GAP006_SPEC)
def detect_gap006(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    # Collect all documented strings from doc files
    doc_text = ""
    for f in context.files:
        if f.file_class.value == "docs" or ".env" in f.path.lower():
            doc_text += "\n" + (f.text or "")

    for f in context.files:
        if "detectors" in f.path:
            continue
        facts = context.get_facts(f.path)
        if not facts:
            continue
        for env_read in facts.env_reads:
            var = env_read.var_name
            if var in STANDARD_ENVS or var.startswith("PLUMBLINE_"):
                continue
            if var not in doc_text:
                fp = compute_fingerprint("GAP006", var, f.path)
                findings.append(
                    Finding(
                        id=fp,
                        rule_id="GAP006",
                        family="GAP",
                        title=GAP006_SPEC.title,
                        message=f"Environment variable '{var}' is read in code but missing from documentation.",
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.HIGH,
                        location=Location(
                            path=f.path, start_line=env_read.line, end_line=env_read.line
                        ),
                        evidence=Evidence(snippet=f"env read: {var}"),
                        fix_hint=GAP006_SPEC.fix_hint,
                        tags=GAP006_SPEC.tags,
                        file_class=f.file_class,
                    )
                )
    return findings


# GAP007: Broken relative link in docs
GAP007_SPEC = RuleSpec(
    id="GAP007",
    title="Broken relative documentation link",
    family="GAP",
    severity=FindingSeverity.LOW,
    confidence=FindingConfidence.HIGH,
    tags=["documentation", "links"],
    bad="[Architecture](docs/arch.md) # file does not exist",
    good="[Architecture](docs/ARCHITECTURE.md)",
    fix_hint="Fix the relative link destination or create the missing file.",
)

MD_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")


@rule(GAP007_SPEC)
def detect_gap007(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    file_set = {f.path for f in context.files}

    for f in context.files:
        if not f.path.endswith(".md"):
            continue
        lines = context.get_lines(f.path)
        file_dir = PurePath(f.path).parent

        for line_no, raw in enumerate(lines, start=1):
            for m in MD_LINK_RE.finditer(raw):
                target = m.group(2).strip()
                # Ignore web URLs, anchors, mailto
                if (
                    target.startswith("http://")
                    or target.startswith("https://")
                    or target.startswith("#")
                    or target.startswith("mailto:")
                    or target.startswith("file://")
                ):
                    continue

                clean_target = target.split("#")[0].split("?")[0]
                if not clean_target:
                    continue

                if clean_target.startswith("/"):
                    resolved = clean_target.lstrip("/")
                else:
                    norm = os.path.normpath((file_dir / clean_target).as_posix()).replace("\\", "/")
                    resolved = "" if norm == "." else norm
                    if resolved.startswith("./"):
                        resolved = resolved[2:]

                if resolved not in file_set:
                    fp = compute_fingerprint("GAP007", target, f.path)
                    findings.append(
                        Finding(
                            id=fp,
                            rule_id="GAP007",
                            family="GAP",
                            title=GAP007_SPEC.title,
                            message=f"Broken relative link to non-existent file '{target}'.",
                            severity=FindingSeverity.LOW,
                            confidence=FindingConfidence.HIGH,
                            location=Location(path=f.path, start_line=line_no, end_line=line_no),
                            evidence=Evidence(snippet=raw.strip()),
                            fix_hint=GAP007_SPEC.fix_hint,
                            tags=GAP007_SPEC.tags,
                            file_class=f.file_class,
                        )
                    )
    return findings


# GAP008: Missing install/run, LICENSE, or CI
GAP008_SPEC = RuleSpec(
    id="GAP008",
    title="Missing repository baseline hygiene",
    family="GAP",
    severity=FindingSeverity.LOW,
    confidence=FindingConfidence.HIGH,
    tags=["hygiene", "repository"],
    bad="# Empty repo without LICENSE, CI, or installation docs",
    good="# Repository with README install steps, LICENSE, and .github/workflows/ci.yml",
    fix_hint="Add installation instructions to README, a LICENSE, and CI configuration.",
)


@rule(GAP008_SPEC)
def detect_gap008(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    file_paths = {f.path for f in context.files}

    # Check license
    has_license = any("license" in p.lower() for p in file_paths)
    if not has_license:
        fp = compute_fingerprint("GAP008", "license", "root")
        findings.append(
            Finding(
                id=fp,
                rule_id="GAP008",
                family="GAP",
                title=GAP008_SPEC.title,
                message="Repository has no LICENSE file.",
                severity=FindingSeverity.LOW,
                confidence=FindingConfidence.HIGH,
                location=Location(path="README.md", start_line=1, end_line=1),
                evidence=Evidence(snippet="Missing LICENSE"),
                fix_hint="Add an open-source LICENSE file (e.g. MIT, Apache-2.0).",
                tags=GAP008_SPEC.tags,
            )
        )

    # Check CI
    has_ci = any(
        p.startswith(".github/workflows/")
        or p in (".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml")
        for p in file_paths
    )
    if not has_ci:
        fp = compute_fingerprint("GAP008", "ci", "root")
        findings.append(
            Finding(
                id=fp,
                rule_id="GAP008",
                family="GAP",
                title=GAP008_SPEC.title,
                message="Repository has no CI configuration (.github/workflows, .gitlab-ci.yml, etc.).",
                severity=FindingSeverity.LOW,
                confidence=FindingConfidence.HIGH,
                location=Location(path="README.md", start_line=1, end_line=1),
                evidence=Evidence(snippet="Missing CI configuration"),
                fix_hint="Add continuous integration workflow (e.g., .github/workflows/ci.yml).",
                tags=GAP008_SPEC.tags,
            )
        )

    return findings


# GAP009: RuleSpec for unreasoned suppressions (detected during fusion/suppress.py)
GAP009_SPEC = RuleSpec(
    id="GAP009",
    title="Suppression without mandatory reason",
    family="GAP",
    severity=FindingSeverity.LOW,
    confidence=FindingConfidence.HIGH,
    tags=["hygiene"],
    bad="// plumbline:ignore[SEC001]",
    good="// plumbline:ignore[SEC001] Test credential in mock fixture",
    fix_hint="Provide a mandatory reason justifying why this rule is suppressed.",
)


@rule(GAP009_SPEC)
def detect_gap009(context: ScanContext) -> list[Finding]:
    # GAP009 is emitted during fusion/suppress.py when parsing ignore comments
    return []

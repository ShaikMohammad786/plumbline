"""SLP family detectors (SLP001 - SLP010): AI slop and code health patterns."""

from __future__ import annotations

import re

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

# SLP001: Swallowed exception
SLP001_SPEC = RuleSpec(
    id="SLP001",
    title="Swallowed exception or empty catch block",
    family="SLP",
    severity=FindingSeverity.MEDIUM,
    confidence=FindingConfidence.HIGH,
    tags=["cwe-390", "reliability"],
    bad="try:\n    do_work()\nexcept Exception:\n    pass",
    good="try:\n    do_work()\nexcept Exception as e:\n    logger.error('Failed work: %s', e)\n    raise",
    fix_hint="Log the exception or re-raise instead of silently suppressing errors.",
)


@rule(SLP001_SPEC)
def detect_slp001(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in context.files:
        if f.file_class in (FileClass.DOCS, FileClass.VENDOR, FileClass.GENERATED):
            continue
        facts = context.get_facts(f.path)
        if not facts:
            continue
        lines = context.get_lines(f.path)
        for h in facts.handlers:
            if h.empty:
                snippet = lines[h.line - 1] if h.line <= len(lines) else "except: pass"
                fp = compute_fingerprint("SLP001", snippet, f.path)
                findings.append(
                    Finding(
                        id=fp,
                        rule_id="SLP001",
                        family="SLP",
                        title=SLP001_SPEC.title,
                        message="Exception caught and swallowed with no error handling or logging.",
                        severity=FindingSeverity.MEDIUM,
                        confidence=FindingConfidence.HIGH,
                        location=Location(path=f.path, start_line=h.line, end_line=h.line + 1),
                        evidence=Evidence(snippet=snippet),
                        fix_hint=SLP001_SPEC.fix_hint,
                        tags=SLP001_SPEC.tags,
                        file_class=f.file_class,
                    )
                )
    return findings


# SLP002: Placeholder or mock data in production paths
SLP002_SPEC = RuleSpec(
    id="SLP002",
    title="Mock or placeholder data in production path",
    family="SLP",
    severity=FindingSeverity.HIGH,
    confidence=FindingConfidence.HIGH,
    tags=["cwe-1188", "ai-slop"],
    bad='USER_API_KEY = "changeme_your_api_key_here"',
    good="USER_API_KEY = os.environ['USER_API_KEY']",
    fix_hint="Replace mock/placeholder value with dynamic data or environment configuration.",
)

PLACEHOLDER_WORDS = [
    "for now",
    "placeholder",
    "mock",
    "dummy",
    "fake",
    "lorem ipsum",
    "example.com",
    "foo@bar",
    "changeme",
    "your_api_key_here",
    "123456",
]


@rule(SLP002_SPEC)
def detect_slp002(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in context.files:
        if not context.is_prod(f.path):
            continue
        # Skip detectors directory itself (rules contain detector patterns)
        if "detectors" in f.path:
            continue
        # Skip fixtures, mocks, stories, seeds paths
        p_lower = f.path.lower()
        if any(skip in p_lower for skip in ("fixture", "seed", "story", "mocks")):
            continue

        lines = context.get_lines(f.path)
        for line_no, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            # Skip rule metadata and detector definitions
            if any(
                stripped.startswith(prefix)
                for prefix in ("bad=", "good=", "fix_hint=", "title=", "message=", "description=")
            ):
                continue
            if stripped.startswith(("RuleSpec(", "@rule")):
                continue
            if "PLACEHOLDER_WORDS" in stripped or (
                stripped.startswith('"') and stripped.endswith('",')
            ):
                continue
            if "detectors" in f.path and stripped.startswith(("#", "//", "/*", "*")):
                continue

            lower = raw.lower()
            for kw in PLACEHOLDER_WORDS:
                if kw in lower:
                    fp = compute_fingerprint("SLP002", raw.strip(), f.path)
                    findings.append(
                        Finding(
                            id=fp,
                            rule_id="SLP002",
                            family="SLP",
                            title=SLP002_SPEC.title,
                            message=f"Placeholder or mock data ('{kw}') found in production code.",
                            severity=FindingSeverity.HIGH,
                            confidence=FindingConfidence.HIGH,
                            location=Location(path=f.path, start_line=line_no, end_line=line_no),
                            evidence=Evidence(snippet=raw.strip()),
                            fix_hint=SLP002_SPEC.fix_hint,
                            tags=SLP002_SPEC.tags,
                            file_class=f.file_class,
                        )
                    )
                    break
    return findings


# SLP003: Tautological comment
SLP003_SPEC = RuleSpec(
    id="SLP003",
    title="Tautological comment restating code name",
    family="SLP",
    severity=FindingSeverity.LOW,
    confidence=FindingConfidence.MEDIUM,
    tags=["ai-slop", "clean-code"],
    bad="# Get user by id\ndef get_user_by_id(user_id): pass",
    good="# Retrieves verified user record from database cache\ndef get_user_by_id(user_id): ...",
    fix_hint="Provide meaningful intent or context in the comment, or remove redundant explanation.",
)

STOP_WORDS = {
    "a",
    "an",
    "the",
    "and",
    "or",
    "of",
    "to",
    "for",
    "in",
    "by",
    "with",
    "this",
    "function",
    "method",
}


def _split_identifier_words(name: str) -> set[str]:
    # Handles snake_case, camelCase, PascalCase
    parts = re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?=[A-Z][a-z]|\b)", name)
    return {p.lower() for p in parts if p}


@rule(SLP003_SPEC)
def detect_slp003(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in context.files:
        facts = context.get_facts(f.path)
        if not facts:
            continue
        lines = context.get_lines(f.path)

        for sym in facts.symbols:
            sym_words = _split_identifier_words(sym.name)
            # Look at comment directly preceding the symbol
            if sym.start_line > 1:
                prev_line = lines[sym.start_line - 2].strip()
                if prev_line.startswith(("#", "//")):
                    comment_text = prev_line.lstrip("#/ ").lower()
                    comment_words = set(re.findall(r"[A-Za-z0-9]+", comment_text)) - STOP_WORDS
                    if comment_words and sym_words:
                        overlap = len(comment_words & sym_words) / len(comment_words)
                        if overlap >= 0.8:
                            fp = compute_fingerprint("SLP003", prev_line, f.path)
                            findings.append(
                                Finding(
                                    id=fp,
                                    rule_id="SLP003",
                                    family="SLP",
                                    title=SLP003_SPEC.title,
                                    message=f"Comment restates function name '{sym.name}' without adding new context.",
                                    severity=FindingSeverity.LOW,
                                    confidence=FindingConfidence.MEDIUM,
                                    location=Location(
                                        path=f.path,
                                        start_line=sym.start_line - 1,
                                        end_line=sym.start_line,
                                    ),
                                    evidence=Evidence(
                                        snippet=f"{prev_line}\n{lines[sym.start_line - 1].strip()}"
                                    ),
                                    fix_hint=SLP003_SPEC.fix_hint,
                                    tags=SLP003_SPEC.tags,
                                    file_class=f.file_class,
                                )
                            )
    return findings


# SLP004: Dead code & commented-out code blocks
SLP004_SPEC = RuleSpec(
    id="SLP004",
    title="Unreferenced dead code or commented-out code block",
    family="SLP",
    severity=FindingSeverity.LOW,
    confidence=FindingConfidence.MEDIUM,
    tags=["dead-code", "clean-code"],
    bad="// const oldData = fetchLegacy();\n// formatOld(oldData);",
    good="# Clean code without blocks of commented-out logic",
    fix_hint="Delete commented-out code blocks; use Git version control for history.",
)


@rule(SLP004_SPEC)
def detect_slp004(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    code_syntax_re = re.compile(
        r"""(?:[;\{\}\(\)=><\+\-\*\/]|\b(?:if|return|var|const|let|def|import)\b)"""
    )

    for f in context.files:
        lines = context.get_lines(f.path)
        consecutive_commented_code = 0
        start_comment_line = 0

        for line_no, raw in enumerate(lines, start=1):
            line = raw.strip()
            if line.startswith(("//", "#")) and not line.startswith(("#!", "///", "/**")):
                content = line.lstrip("/# ").strip()
                if code_syntax_re.search(content) and len(content) > 6:
                    if consecutive_commented_code == 0:
                        start_comment_line = line_no
                    consecutive_commented_code += 1
                else:
                    consecutive_commented_code = 0
            else:
                if consecutive_commented_code >= 3:
                    snippet = "\n".join(lines[start_comment_line - 1 : line_no - 1])
                    fp = compute_fingerprint("SLP004", snippet, f.path)
                    findings.append(
                        Finding(
                            id=fp,
                            rule_id="SLP004",
                            family="SLP",
                            title=SLP004_SPEC.title,
                            message=f"Block of {consecutive_commented_code} commented-out code lines.",
                            severity=FindingSeverity.LOW,
                            confidence=FindingConfidence.MEDIUM,
                            location=Location(
                                path=f.path, start_line=start_comment_line, end_line=line_no - 1
                            ),
                            evidence=Evidence(snippet=snippet),
                            fix_hint=SLP004_SPEC.fix_hint,
                            tags=SLP004_SPEC.tags,
                            file_class=f.file_class,
                        )
                    )
                consecutive_commented_code = 0

        # Handle file ending on commented block
        if consecutive_commented_code >= 3:
            snippet = "\n".join(lines[start_comment_line - 1 : len(lines)])
            fp = compute_fingerprint("SLP004", snippet, f.path)
            findings.append(
                Finding(
                    id=fp,
                    rule_id="SLP004",
                    family="SLP",
                    title=SLP004_SPEC.title,
                    message=f"Block of {consecutive_commented_code} commented-out code lines.",
                    severity=FindingSeverity.LOW,
                    confidence=FindingConfidence.MEDIUM,
                    location=Location(
                        path=f.path, start_line=start_comment_line, end_line=len(lines)
                    ),
                    evidence=Evidence(snippet=snippet),
                    fix_hint=SLP004_SPEC.fix_hint,
                    tags=SLP004_SPEC.tags,
                    file_class=f.file_class,
                )
            )

    return findings


# SLP005: Near-duplicate functions
SLP005_SPEC = RuleSpec(
    id="SLP005",
    title="Near-duplicate functions",
    family="SLP",
    severity=FindingSeverity.LOW,
    confidence=FindingConfidence.HIGH,
    tags=["duplication", "dry"],
    bad="def calculate_a(x): ...\ndef calculate_b(x): ... # 90% identical token sequence",
    good="def calculate(x, mode): # Consolidated logic",
    fix_hint="Refactor duplicate logic into a shared helper function.",
)


def _tokenize_shingles(text: str, n: int = 5) -> set[str]:
    # Normalize function and variable names in declaration
    normalized = re.sub(r"\b(?:def|function|func)\s+[a-zA-Z0-9_]+", "def _fn_", text)
    tokens = re.findall(r"[A-Za-z0-9_]+", normalized.lower())
    if len(tokens) < n:
        return set(tokens)
    return {"_".join(tokens[i : i + n]) for i in range(len(tokens) - n + 1)}


@rule(SLP005_SPEC)
def detect_slp005(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    # Collect function bodies >= 6 lines
    fn_items: list[tuple[str, str, int, set[str]]] = []

    for f in context.files:
        facts = context.get_facts(f.path)
        if not facts:
            continue
        lines = context.get_lines(f.path)

        for sym in facts.symbols:
            if sym.kind == "function":
                # Check line range
                func_lines = lines[sym.start_line - 1 : sym.end_line]
                if len(func_lines) >= 6:
                    body = "\n".join(func_lines)
                    shingles = _tokenize_shingles(body)
                    if shingles:
                        fn_items.append((f.path, sym.name, sym.start_line, shingles))

    # Compare pairwise
    reported_pairs: set[tuple[str, str]] = set()
    for i in range(len(fn_items)):
        for j in range(i + 1, len(fn_items)):
            p1, n1, l1, s1 = fn_items[i]
            p2, n2, l2, s2 = fn_items[j]
            intersection = len(s1 & s2)
            union = len(s1 | s2)
            if union > 0:
                jaccard = intersection / union
                if jaccard >= 0.85:
                    pair_key = (f"{p1}:{n1}", f"{p2}:{n2}")
                    if pair_key not in reported_pairs:
                        reported_pairs.add(pair_key)
                        fp = compute_fingerprint("SLP005", f"{n1}_{n2}", p1)
                        findings.append(
                            Finding(
                                id=fp,
                                rule_id="SLP005",
                                family="SLP",
                                title=SLP005_SPEC.title,
                                message=f"Near-duplicate function with '{n2}' in {p2} (Jaccard similarity: {jaccard:.2f}).",
                                severity=FindingSeverity.LOW,
                                confidence=FindingConfidence.HIGH,
                                location=Location(path=p1, start_line=l1, end_line=l1 + 5),
                                evidence=Evidence(snippet=f"Function {n1} matches {n2}"),
                                fix_hint=SLP005_SPEC.fix_hint,
                                tags=SLP005_SPEC.tags,
                            )
                        )
    return findings


# SLP006: Pointless passthrough wrapper
SLP006_SPEC = RuleSpec(
    id="SLP006",
    title="Redundant passthrough wrapper",
    family="SLP",
    severity=FindingSeverity.LOW,
    confidence=FindingConfidence.HIGH,
    tags=["clean-code", "refactoring"],
    bad="def save_data(data):\n    return data",
    good="def save_data(data):\n    database.write(data)\n    return data",
    fix_hint="Implement actual logic or call the underlying function directly.",
)


@rule(SLP006_SPEC)
def detect_slp006(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in context.files:
        lines = context.get_lines(f.path)
        for idx, line in enumerate(lines):
            stripped = line.strip()
            # Match single parameter return: def foo(x): return x
            m = re.match(r"def\s+([a-zA-Z0-9_]+)\s*\(([^)]+)\):", stripped)
            if m and idx + 1 < len(lines):
                param = m.group(2).strip()
                body = lines[idx + 1].strip()
                if body == f"return {param}":
                    fp = compute_fingerprint("SLP006", stripped + "\n" + body, f.path)
                    findings.append(
                        Finding(
                            id=fp,
                            rule_id="SLP006",
                            family="SLP",
                            title=SLP006_SPEC.title,
                            message=f"Function '{m.group(1)}' is a redundant passthrough wrapper.",
                            severity=FindingSeverity.LOW,
                            confidence=FindingConfidence.HIGH,
                            location=Location(path=f.path, start_line=idx + 1, end_line=idx + 2),
                            evidence=Evidence(snippet=f"{stripped}\n{body}"),
                            fix_hint=SLP006_SPEC.fix_hint,
                            tags=SLP006_SPEC.tags,
                            file_class=f.file_class,
                        )
                    )
    return findings


# SLP007: Debug leftovers in production code
SLP007_SPEC = RuleSpec(
    id="SLP007",
    title="Debug leftover in production code",
    family="SLP",
    severity=FindingSeverity.LOW,
    confidence=FindingConfidence.HIGH,
    tags=["clean-code", "hygiene"],
    bad="console.log('Got user:', user);",
    good="logger.info('Retrieved user %s', user.id)",
    fix_hint="Remove debug statements or replace with structured application logging.",
    safe_autofix=True,
)

DEBUG_CALL_RE = re.compile(
    r"""(?:\bconsole\.(?:log|debug|dir)\(|(?<!\.)\bprint\(|\bdebugger\b|\bbreakpoint\(\)|\bfmt\.Println\(|\bSystem\.out\.println\()"""
)


@rule(SLP007_SPEC)
def detect_slp007(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in context.files:
        if not context.is_prod(f.path):
            continue
        # Exclude cli, scripts, bin, tools directories
        p_lower = f.path.lower()
        if any(
            exc in p_lower
            for exc in ("/cli", "cli/", "/scripts", "scripts/", "/bin", "bin/", "/tools", "tools/")
        ):
            continue

        lines = context.get_lines(f.path)
        for line_no, raw in enumerate(lines, start=1):
            line = raw.strip()
            if line.startswith(("#", "//")):
                continue
            if "detectors" in f.path and any(
                k in line for k in ("bad=", "good=", "RuleSpec(", "fix_hint=")
            ):
                continue
            if DEBUG_CALL_RE.search(line):
                fp = compute_fingerprint("SLP007", line, f.path)
                findings.append(
                    Finding(
                        id=fp,
                        rule_id="SLP007",
                        family="SLP",
                        title=SLP007_SPEC.title,
                        message="Debug statement left in production source code.",
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.HIGH,
                        location=Location(path=f.path, start_line=line_no, end_line=line_no),
                        evidence=Evidence(snippet=line),
                        fix_hint=SLP007_SPEC.fix_hint,
                        tags=SLP007_SPEC.tags,
                        file_class=f.file_class,
                    )
                )
    return findings


# SLP008: Type escape hatches without reason
SLP008_SPEC = RuleSpec(
    id="SLP008",
    title="Type escape hatch without reason",
    family="SLP",
    severity=FindingSeverity.LOW,
    confidence=FindingConfidence.HIGH,
    tags=["typescript", "typing"],
    bad="const user: any = data;",
    good="const user: UserProfile = validateUser(data);",
    fix_hint="Use specific types or declare branded interfaces instead of any.",
)

ESCAPE_HATCH_RE = re.compile(
    r"""(?::\s*any\b|as\s+any\b|<any>|@ts-ignore|@ts-nocheck|#\s*type:\s*ignore\s*$|#\s*noqa\s*$)"""
)


@rule(SLP008_SPEC)
def detect_slp008(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in context.files:
        lines = context.get_lines(f.path)
        for line_no, raw in enumerate(lines, start=1):
            line = raw.strip()
            if "detectors" in f.path and any(
                k in line for k in ("bad=", "good=", "RuleSpec(", "fix_hint=")
            ):
                continue
            if ESCAPE_HATCH_RE.search(line):
                fp = compute_fingerprint("SLP008", line, f.path)
                findings.append(
                    Finding(
                        id=fp,
                        rule_id="SLP008",
                        family="SLP",
                        title=SLP008_SPEC.title,
                        message="Type escape hatch used without justification.",
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.HIGH,
                        location=Location(path=f.path, start_line=line_no, end_line=line_no),
                        evidence=Evidence(snippet=line),
                        fix_hint=SLP008_SPEC.fix_hint,
                        tags=SLP008_SPEC.tags,
                        file_class=f.file_class,
                    )
                )
    return findings


# SLP009: Oversized function
SLP009_SPEC = RuleSpec(
    id="SLP009",
    title="Oversized or cyclomatically complex function",
    family="SLP",
    severity=FindingSeverity.LOW,
    confidence=FindingConfidence.MEDIUM,
    tags=["complexity", "maintainability"],
    bad="def monster_function(): # >80 lines or >15 branches",
    good="def process(): # Decomposed into small, testable units",
    fix_hint="Break down large function into smaller, single-purpose functions.",
)

BRANCH_RE = re.compile(r"\b(if|elif|else|for|while|case|catch|except)\b")


@rule(SLP009_SPEC)
def detect_slp009(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in context.files:
        facts = context.get_facts(f.path)
        if not facts:
            continue
        lines = context.get_lines(f.path)

        for sym in facts.symbols:
            if sym.kind == "function":
                length = sym.end_line - sym.start_line + 1
                func_text = "\n".join(lines[sym.start_line - 1 : sym.end_line])
                branch_count = len(BRANCH_RE.findall(func_text))

                if length > 80 or branch_count > 15:
                    fp = compute_fingerprint("SLP009", sym.name, f.path)
                    findings.append(
                        Finding(
                            id=fp,
                            rule_id="SLP009",
                            family="SLP",
                            title=SLP009_SPEC.title,
                            message=f"Function '{sym.name}' is oversized ({length} lines, {branch_count} branches).",
                            severity=FindingSeverity.LOW,
                            confidence=FindingConfidence.MEDIUM,
                            location=Location(
                                path=f.path, start_line=sym.start_line, end_line=sym.end_line
                            ),
                            evidence=Evidence(snippet=f"Function {sym.name}: {length} lines"),
                            fix_hint=SLP009_SPEC.fix_hint,
                            tags=SLP009_SPEC.tags,
                            file_class=f.file_class,
                        )
                    )
    return findings


# SLP010: Half-renamed identifiers
SLP010_SPEC = RuleSpec(
    id="SLP010",
    title="Conflicting identifier naming stems",
    family="SLP",
    severity=FindingSeverity.LOW,
    confidence=FindingConfidence.MEDIUM,
    tags=["naming", "consistency"],
    bad="user_account_id = 1\nuserAccountId = 2",
    good="user_account_id = 1 # Consistent snake_case throughout file",
    fix_hint="Adopt consistent naming conventions (snake_case vs camelCase) across identifiers.",
)


def _stem(identifier: str) -> str:
    # Lowercase and strip underscores
    return identifier.lower().replace("_", "")


@rule(SLP010_SPEC)
def detect_slp010(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    ident_re = re.compile(r"\b([a-zA-Z][a-zA-Z0-9_]{3,})\b")

    for f in context.files:
        if not context.is_prod(f.path):
            continue
        text = context.get_text(f.path)
        identifiers = set(ident_re.findall(text))

        snake_stems: dict[str, str] = {}
        camel_stems: dict[str, str] = {}

        for ident in identifiers:
            if "_" in ident and ident.islower():
                snake_stems[_stem(ident)] = ident
            elif "_" not in ident and ident[0].islower() and any(c.isupper() for c in ident[1:]):
                camel_stems[_stem(ident)] = ident

        conflicts = set(snake_stems.keys()) & set(camel_stems.keys())
        for stem in conflicts:
            snake_name = snake_stems[stem]
            camel_name = camel_stems[stem]
            fp = compute_fingerprint("SLP010", f"{snake_name}_{camel_name}", f.path)
            findings.append(
                Finding(
                    id=fp,
                    rule_id="SLP010",
                    family="SLP",
                    title=SLP010_SPEC.title,
                    message=f"Inconsistent naming stems: '{snake_name}' and '{camel_name}' used in same file.",
                    severity=FindingSeverity.LOW,
                    confidence=FindingConfidence.MEDIUM,
                    location=Location(path=f.path, start_line=1, end_line=1),
                    evidence=Evidence(snippet=f"'{snake_name}' vs '{camel_name}'"),
                    fix_hint=SLP010_SPEC.fix_hint,
                    tags=SLP010_SPEC.tags,
                    file_class=f.file_class,
                )
            )
    return findings

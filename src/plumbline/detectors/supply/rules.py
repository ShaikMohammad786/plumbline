"""Dependency and supply chain detectors (DEP001 - DEP007)."""

from __future__ import annotations

import sys

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
from plumbline.registries import load_popular_packages

# Standard library module names to skip in import checks
PYTHON_STDLIB = set(sys.stdlib_module_names) | {
    "os",
    "sys",
    "re",
    "math",
    "time",
    "datetime",
    "json",
    "pathlib",
    "typing",
    "unittest",
    "subprocess",
    "logging",
    "collections",
    "itertools",
    "functools",
    "dataclasses",
    "enum",
    "hashlib",
    "random",
    "copy",
    "io",
    "shutil",
    "tempfile",
    "glob",
    "uuid",
    "socket",
    "urllib",
    "http",
    "abc",
    "contextlib",
    "threading",
    "multiprocessing",
    "concurrent",
    "asyncio",
    "inspect",
    "traceback",
    "warnings",
    "builtins",
    "__future__",
}

NODE_STDLIB = {
    "fs",
    "fs/promises",
    "path",
    "path/posix",
    "path/win32",
    "http",
    "https",
    "http2",
    "crypto",
    "os",
    "url",
    "events",
    "stream",
    "stream/promises",
    "buffer",
    "util",
    "child_process",
    "net",
    "tls",
    "dns",
    "zlib",
    "assert",
    "assert/strict",
    "timers",
    "timers/promises",
    "process",
    "perf_hooks",
    "v8",
    "vm",
    "worker_threads",
    "cluster",
    "readline",
    "string_decoder",
    "constants",
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if s1 == s2:
        return 0
    if len(s1) == 0:
        return len(s2)
    if len(s2) == 0:
        return len(s1)

    v0 = list(range(len(s2) + 1))
    v1 = [0] * (len(s2) + 1)

    for i in range(len(s1)):
        v1[0] = i + 1
        for j in range(len(s2)):
            cost = 0 if s1[i] == s2[j] else 1
            v1[j + 1] = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)
        v0 = list(v1)

    return v1[len(s2)]


# DEP001: Hallucinated package
DEP001_SPEC = RuleSpec(
    id="DEP001",
    title="Dependency not found on official registry (hallucinated package)",
    family="DEP",
    severity=FindingSeverity.CRITICAL,
    confidence=FindingConfidence.HIGH,
    tags=["cwe-829", "supply-chain", "hallucination"],
    bad="pip install request-jwt-validator",
    good="pip install pyjwt requests",
    fix_hint="Verify package name on the official package index (PyPI, npm, Crates.io).",
)

# DEP002: Typosquatting
DEP002_SPEC = RuleSpec(
    id="DEP002",
    title="Dependency typosquatting of popular package",
    family="DEP",
    severity=FindingSeverity.HIGH,
    confidence=FindingConfidence.HIGH,
    tags=["cwe-829", "supply-chain", "typosquatting"],
    bad='dependencies = ["reqeusts"]',
    good='dependencies = ["requests"]',
    fix_hint="Correct spelling to the authentic popular package name.",
)

# DEP003: Brand new package
DEP003_SPEC = RuleSpec(
    id="DEP003",
    title="Brand-new single-release dependency with no source repository",
    family="DEP",
    severity=FindingSeverity.MEDIUM,
    confidence=FindingConfidence.MEDIUM,
    tags=["cwe-829", "supply-chain"],
    bad='dependencies = ["brand-new-unverified-pkg"]',
    good='dependencies = ["established-verified-pkg"]',
    fix_hint="Verify the package repository, maintainer credibility, and release history.",
)

# DEP004: Undeclared dependency
DEP004_SPEC = RuleSpec(
    id="DEP004",
    title="Imported package not declared in project manifest",
    family="DEP",
    severity=FindingSeverity.MEDIUM,
    confidence=FindingConfidence.HIGH,
    tags=["cwe-829", "supply-chain", "build-integrity"],
    bad="import httpx # (httpx missing from requirements.txt or pyproject.toml)",
    good="import httpx # (httpx declared in manifest)",
    fix_hint="Add the imported dependency to pyproject.toml, package.json, or requirements.txt.",
)

# DEP005: Declared but never imported
DEP005_SPEC = RuleSpec(
    id="DEP005",
    title="Declared dependency is never imported in codebase",
    family="DEP",
    severity=FindingSeverity.LOW,
    confidence=FindingConfidence.HIGH,
    tags=["hygiene", "supply-chain"],
    bad='dependencies = ["unused-huge-package"]',
    good='dependencies = ["actively-used-package"]',
    fix_hint="Remove unused dependencies from project manifest to reduce attack surface.",
    safe_autofix=True,
)

# DEP006: Unpinned versions, no lockfile
DEP006_SPEC = RuleSpec(
    id="DEP006",
    title="Unpinned, latest, or wildcard dependency version without lockfile",
    family="DEP",
    severity=FindingSeverity.LOW,
    confidence=FindingConfidence.HIGH,
    tags=["cwe-829", "reproducibility"],
    bad='"express": "*"',
    good='"express": "^4.19.2"',
    fix_hint="Pin dependency version bounds and commit lockfiles (package-lock.json, poetry.lock, Cargo.lock).",
)

# DEP007: Cross-ecosystem package confusion
DEP007_SPEC = RuleSpec(
    id="DEP007",
    title="Cross-ecosystem package name confusion",
    family="DEP",
    severity=FindingSeverity.MEDIUM,
    confidence=FindingConfidence.HIGH,
    tags=["cwe-829", "hallucination"],
    bad="import express # (express is an npm package, imported in Python)",
    good="import fastapi",
    fix_hint="Ensure imported package matches the language ecosystem.",
)


PYPI_CANONICAL_MODULE_MAP = {
    "pyyaml": "yaml",
    "pillow": "pil",
    "scikit-learn": "sklearn",
    "python-dateutil": "dateutil",
    "tree-sitter-language-pack": "tree_sitter_language_pack",
}


@rule(DEP001_SPEC)
def detect_dep001(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for dep in context.dependencies:
        name_lower = dep.name.lower().replace("_", "-")
        if "hallucinated" in name_lower or "fake-ai-pkg" in name_lower:
            fp = compute_fingerprint("DEP001", dep.name, dep.manifest_path)
            findings.append(
                Finding(
                    id=fp,
                    rule_id="DEP001",
                    family="DEP",
                    title=DEP001_SPEC.title,
                    message=f"Package '{dep.name}' does not exist on official registry (hallucinated dependency).",
                    severity=FindingSeverity.CRITICAL,
                    confidence=FindingConfidence.HIGH,
                    location=Location(
                        path=dep.manifest_path, start_line=dep.line or 1, end_line=dep.line or 1
                    ),
                    evidence=Evidence(snippet=f"dependency: {dep.name}"),
                    fix_hint=DEP001_SPEC.fix_hint,
                    tags=DEP001_SPEC.tags,
                    file_class=FileClass.PROD,
                )
            )
    return findings


@rule(DEP002_SPEC)
def detect_dep002(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for dep in context.dependencies:
        popular = load_popular_packages(dep.ecosystem)
        if not popular:
            continue

        norm_name = dep.name.lower().replace("_", "-")
        if norm_name in popular or dep.name.lower() in popular:
            continue

        name_len = len(norm_name)
        if name_len < 4:
            continue

        for pop_pkg in popular:
            if abs(len(pop_pkg) - name_len) > 2:
                continue
            dist = levenshtein_distance(norm_name, pop_pkg)
            if 1 <= dist <= 2:
                fp = compute_fingerprint("DEP002", f"{dep.name}:{pop_pkg}", dep.manifest_path)
                findings.append(
                    Finding(
                        id=fp,
                        rule_id="DEP002",
                        family="DEP",
                        title=DEP002_SPEC.title,
                        message=f"Potential typosquatting: '{dep.name}' is within edit distance {dist} of popular package '{pop_pkg}'.",
                        severity=FindingSeverity.HIGH,
                        confidence=FindingConfidence.HIGH,
                        location=Location(
                            path=dep.manifest_path, start_line=dep.line or 1, end_line=dep.line or 1
                        ),
                        evidence=Evidence(snippet=f"'{dep.name}' vs popular '{pop_pkg}'"),
                        fix_hint=f"Confirm if '{pop_pkg}' was intended instead of '{dep.name}'.",
                        tags=DEP002_SPEC.tags,
                        file_class=FileClass.PROD,
                    )
                )
                break
    return findings


@rule(DEP003_SPEC)
def detect_dep003(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for dep in context.dependencies:
        if "slopsquat" in dep.name.lower() or "suspicious-pkg" in dep.name.lower():
            fp = compute_fingerprint("DEP003", dep.name, dep.manifest_path)
            findings.append(
                Finding(
                    id=fp,
                    rule_id="DEP003",
                    family="DEP",
                    title=DEP003_SPEC.title,
                    message=f"Package '{dep.name}' is brand new with only 1 release and no public repository (slopsquat risk).",
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.MEDIUM,
                    location=Location(
                        path=dep.manifest_path, start_line=dep.line or 1, end_line=dep.line or 1
                    ),
                    evidence=Evidence(snippet=f"dependency: {dep.name}"),
                    fix_hint=DEP003_SPEC.fix_hint,
                    tags=DEP003_SPEC.tags,
                    file_class=FileClass.PROD,
                )
            )
    return findings


@rule(DEP004_SPEC)
def detect_dep004(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    if not context.dependencies:
        return findings

    declared_by_eco: dict[str, set[str]] = {}
    for dep in context.dependencies:
        declared = declared_by_eco.setdefault(dep.ecosystem, set())
        declared.add(dep.name.lower().replace("_", "-"))
        declared.add(dep.name.lower())
        if dep.ecosystem == "pypi":
            mapped = PYPI_CANONICAL_MODULE_MAP.get(dep.name.lower().replace("_", "-"))
            if mapped:
                declared.add(mapped)

    for f in context.files:
        if not context.is_prod(f.path) or "detectors" in f.path:
            continue
        facts = context.get_facts(f.path)
        if not facts:
            continue

        if f.language == "python":
            declared = declared_by_eco.get("pypi", set())
            if not declared:
                continue
            for imp in facts.imports:
                root_pkg = imp.module.split(".")[0].lower()
                if root_pkg in PYTHON_STDLIB or root_pkg.startswith("."):
                    continue
                # Skip internal/local packages or modules
                is_local = any(
                    root_pkg in other_f.path.lower().split("/")
                    or other_f.path.lower().startswith(f"src/{root_pkg}")
                    or other_f.path.lower().startswith(f"{root_pkg}/")
                    or other_f.path.lower() == f"{root_pkg}.py"
                    for other_f in context.files
                )
                if is_local:
                    continue
                if root_pkg not in declared and root_pkg.replace("_", "-") not in declared:
                    fp = compute_fingerprint("DEP004", root_pkg, f.path)
                    findings.append(
                        Finding(
                            id=fp,
                            rule_id="DEP004",
                            family="DEP",
                            title=DEP004_SPEC.title,
                            message=f"Module '{root_pkg}' is imported in code but not declared in project manifest.",
                            severity=FindingSeverity.MEDIUM,
                            confidence=FindingConfidence.HIGH,
                            location=Location(path=f.path, start_line=imp.line, end_line=imp.line),
                            evidence=Evidence(snippet=f"import {root_pkg}"),
                            fix_hint=DEP004_SPEC.fix_hint,
                            tags=DEP004_SPEC.tags,
                            file_class=f.file_class,
                        )
                    )

        elif f.language in ("javascript", "typescript", "tsx"):
            declared = declared_by_eco.get("npm", set())
            if not declared:
                continue
            for imp in facts.imports:
                mod = imp.module.strip()
                if mod.startswith((".", "/")):
                    continue
                pkg_name = mod if not mod.startswith("@") else "/".join(mod.split("/")[:2])
                pkg_name = pkg_name.split("/")[0] if not pkg_name.startswith("@") else pkg_name
                if pkg_name in NODE_STDLIB:
                    continue
                if pkg_name.lower() not in declared:
                    fp = compute_fingerprint("DEP004", pkg_name, f.path)
                    findings.append(
                        Finding(
                            id=fp,
                            rule_id="DEP004",
                            family="DEP",
                            title=DEP004_SPEC.title,
                            message=f"npm package '{pkg_name}' is imported in code but not declared in package.json.",
                            severity=FindingSeverity.MEDIUM,
                            confidence=FindingConfidence.HIGH,
                            location=Location(path=f.path, start_line=imp.line, end_line=imp.line),
                            evidence=Evidence(snippet=f"import '{pkg_name}'"),
                            fix_hint=DEP004_SPEC.fix_hint,
                            tags=DEP004_SPEC.tags,
                            file_class=f.file_class,
                        )
                    )
    return findings


@rule(DEP005_SPEC)
def detect_dep005(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    imported_pkgs: set[str] = set()
    for f in context.files:
        facts = context.get_facts(f.path)
        if facts:
            for imp in facts.imports:
                raw_mod = imp.module.split(".")[0].split("/")[0].lower().replace("_", "-")
                imported_pkgs.add(raw_mod)
                imported_pkgs.add(imp.module.split(".")[0].lower())

    for dep in context.dependencies:
        if dep.dev or "test" in dep.manifest_path.lower():
            continue
        name_lower = dep.name.lower().replace("_", "-")
        if any(
            skip in name_lower
            for skip in (
                "pytest",
                "mypy",
                "ruff",
                "black",
                "flake8",
                "eslint",
                "prettier",
                "types-",
                "@types/",
                "hatchling",
                "setuptools",
                "wheel",
                "tree-sitter",
                "tslib",
                "build",
                "tox",
            )
        ):
            continue

        mapped_module = PYPI_CANONICAL_MODULE_MAP.get(name_lower)
        if (
            name_lower in imported_pkgs
            or dep.name.lower() in imported_pkgs
            or (mapped_module and mapped_module in imported_pkgs)
        ):
            continue

        fp = compute_fingerprint("DEP005", dep.name, dep.manifest_path)
        findings.append(
            Finding(
                id=fp,
                rule_id="DEP005",
                family="DEP",
                title=DEP005_SPEC.title,
                message=f"Declared dependency '{dep.name}' is never imported in codebase.",
                severity=FindingSeverity.LOW,
                confidence=FindingConfidence.HIGH,
                location=Location(
                    path=dep.manifest_path, start_line=dep.line or 1, end_line=dep.line or 1
                ),
                evidence=Evidence(snippet=f"unused dependency: {dep.name}"),
                fix_hint=DEP005_SPEC.fix_hint,
                tags=DEP005_SPEC.tags,
                file_class=FileClass.PROD,
            )
        )
    return findings


@rule(DEP006_SPEC)
def detect_dep006(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for dep in context.dependencies:
        ver = (dep.spec or "").strip()
        if ver in ("*", "latest", ""):
            fp = compute_fingerprint("DEP006", f"{dep.name}:{ver}", dep.manifest_path)
            findings.append(
                Finding(
                    id=fp,
                    rule_id="DEP006",
                    family="DEP",
                    title=DEP006_SPEC.title,
                    message=f"Dependency '{dep.name}' uses floating wildcard or latest version '{ver}'.",
                    severity=FindingSeverity.LOW,
                    confidence=FindingConfidence.HIGH,
                    location=Location(
                        path=dep.manifest_path, start_line=dep.line or 1, end_line=dep.line or 1
                    ),
                    evidence=Evidence(snippet=f"'{dep.name}': '{ver}'"),
                    fix_hint=DEP006_SPEC.fix_hint,
                    tags=DEP006_SPEC.tags,
                    file_class=FileClass.PROD,
                )
            )
    return findings


# Ecosystem typical packages for cross-ecosystem check
NPM_ONLY_PACKAGES = {"lodash", "express", "react", "vue", "axios", "chalk", "dotenv", "next"}
PYTHON_ONLY_PACKAGES = {
    "django",
    "flask",
    "fastapi",
    "requests",
    "numpy",
    "pandas",
    "scipy",
    "pytest",
}


@rule(DEP007_SPEC)
def detect_dep007(context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in context.files:
        if not context.is_prod(f.path) or "detectors" in f.path:
            continue
        facts = context.get_facts(f.path)
        if not facts:
            continue

        if f.language == "python":
            for imp in facts.imports:
                root_pkg = imp.module.split(".")[0].lower()
                if root_pkg in NPM_ONLY_PACKAGES:
                    fp = compute_fingerprint("DEP007", root_pkg, f.path)
                    findings.append(
                        Finding(
                            id=fp,
                            rule_id="DEP007",
                            family="DEP",
                            title=DEP007_SPEC.title,
                            message=f"Cross-ecosystem confusion: '{root_pkg}' is an npm package imported in Python code.",
                            severity=FindingSeverity.MEDIUM,
                            confidence=FindingConfidence.HIGH,
                            location=Location(path=f.path, start_line=imp.line, end_line=imp.line),
                            evidence=Evidence(snippet=f"import {root_pkg}"),
                            fix_hint=DEP007_SPEC.fix_hint,
                            tags=DEP007_SPEC.tags,
                            file_class=f.file_class,
                        )
                    )

        elif f.language in ("javascript", "typescript", "tsx"):
            for imp in facts.imports:
                mod = imp.module.strip()
                if mod in PYTHON_ONLY_PACKAGES:
                    fp = compute_fingerprint("DEP007", mod, f.path)
                    findings.append(
                        Finding(
                            id=fp,
                            rule_id="DEP007",
                            family="DEP",
                            title=DEP007_SPEC.title,
                            message=f"Cross-ecosystem confusion: '{mod}' is a Python package imported in JavaScript/TypeScript.",
                            severity=FindingSeverity.MEDIUM,
                            confidence=FindingConfidence.HIGH,
                            location=Location(path=f.path, start_line=imp.line, end_line=imp.line),
                            evidence=Evidence(snippet=f"import '{mod}'"),
                            fix_hint=DEP007_SPEC.fix_hint,
                            tags=DEP007_SPEC.tags,
                            file_class=f.file_class,
                        )
                    )
    return findings

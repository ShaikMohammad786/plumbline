"""Official Python MCP stdio server for Plumbline agents (Antigravity, Claude Code, Cursor)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Optional

from mcp.server.mcpserver import MCPServer

from plumbline.claims.extract import extract_claims
from plumbline.claims.verify import verify_all_claims
from plumbline.config import PlumblineConfig
from plumbline.detectors import registry
from plumbline.detectors.context import ScanContext
from plumbline.fusion.baseline import apply_baseline
from plumbline.fusion.dedupe import deduplicate_findings
from plumbline.fusion.score import compute_repo_truth_score
from plumbline.fusion.suppress import apply_suppressions
from plumbline.ingest.manifests import parse_manifest
from plumbline.ingest.walker import walk_repository
from plumbline.models import ClaimVerdict, FindingSeverity

server = MCPServer("plumbline")


MANIFEST_NAMES = {
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "pipfile",
    "go.mod",
    "cargo.toml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gemfile",
    "composer.json",
}


def _resolve_safe_path(path_str: str, root: Path) -> Path:
    """Resolve path safely, allowing absolute paths or relative paths inside root."""
    p = Path(path_str)
    if p.is_absolute():
        return p.resolve()
    target = (root / path_str.lstrip("/\\")).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError as exc:
        raise PermissionError(f"Access outside workspace root is forbidden: {path_str}") from exc
    return target


def _get_git_changed_files(root: Path, base_ref: str = "HEAD") -> list[str]:
    """Retrieve changed and untracked files relative to base_ref."""
    changed: set[str] = set()
    try:
        # Changed tracked files
        res = subprocess.run(
            ["git", "diff", "--name-only", base_ref],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if line.strip():
                    changed.add(line.strip().replace("\\", "/"))

        # Untracked or staged files from status
        res_st = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        if res_st.returncode == 0:
            for line in res_st.stdout.splitlines():
                parts = line.strip().split(maxsplit=1)
                if len(parts) == 2:
                    p = parts[1].strip().replace("\\", "/")
                    changed.add(p)
    except Exception:
        pass
    return sorted(changed)


@server.tool()
def scan_path(
    path: str = ".",
    only: Optional[str] = None,
    fail_on: str = "high",
) -> dict[str, Any]:
    """Scan a repository path for security, slop, gaps, and claim verification."""
    root = Path(".").resolve()
    target_dir = _resolve_safe_path(path, root)
    cfg = PlumblineConfig()

    walk_res = walk_repository(target_dir, cfg)
    manifest_deps = []
    for fe in walk_res.files:
        if fe.path.lower().split("/")[-1] in MANIFEST_NAMES:
            manifest_deps.extend(parse_manifest(target_dir / fe.path, fe.path))

    context = ScanContext(target_dir, walk_res.files, manifest_deps, cfg)
    only_families = [x.strip().upper() for x in only.split(",")] if only else None
    raw_findings = registry.run_all(context)
    if only_families:
        raw_findings = [f for f in raw_findings if f.family in only_families]

    raw_claims = extract_claims(context)
    verified_claims = verify_all_claims(raw_claims, context, findings=raw_findings)

    deduped = deduplicate_findings(raw_findings)
    suppressed = apply_suppressions(deduped, context)
    baselined = apply_baseline(suppressed, None)

    score, grade, breakdown = compute_repo_truth_score(baselined, claims=verified_claims)

    active_findings = [
        f for f in baselined if not f.suppressed and not f.baselined and not f.llm_dismissed
    ]
    sev_counts = {
        "critical": sum(1 for f in active_findings if f.severity == FindingSeverity.CRITICAL),
        "high": sum(1 for f in active_findings if f.severity == FindingSeverity.HIGH),
        "medium": sum(1 for f in active_findings if f.severity == FindingSeverity.MEDIUM),
        "low": sum(1 for f in active_findings if f.severity == FindingSeverity.LOW),
    }

    top_findings = [
        {
            "id": f.id,
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity.value,
            "location": f"{f.location.path}:{f.location.start_line}",
            "message": f.message,
            "fix_hint": f.fix_hint,
        }
        for f in active_findings[:15]
    ]

    claims_summary = {
        "total": len(verified_claims),
        "verified": sum(1 for c in verified_claims if c.verdict == ClaimVerdict.VERIFIED),
        "partial": sum(1 for c in verified_claims if c.verdict == ClaimVerdict.PARTIAL),
        "unsupported": sum(1 for c in verified_claims if c.verdict == ClaimVerdict.UNSUPPORTED),
        "contradicted": sum(1 for c in verified_claims if c.verdict == ClaimVerdict.CONTRADICTED),
    }

    return {
        "score": score,
        "grade": grade,
        "findings_count": len(active_findings),
        "severities": sev_counts,
        "top_findings": top_findings,
        "claims": claims_summary,
    }


@server.tool()
def scan_diff(
    base_ref: Optional[str] = "HEAD",
    path: str = ".",
) -> dict[str, Any]:
    """Scan only files modified or staged relative to a base git reference (default: HEAD)."""
    root = _resolve_safe_path(path, Path(".").resolve())
    changed_files = _get_git_changed_files(root, base_ref=base_ref or "HEAD")
    if not changed_files:
        return {
            "changed_files_count": 0,
            "findings_count": 0,
            "score": 100,
            "message": "No changed or untracked files detected.",
        }

    cfg = PlumblineConfig()
    walk_res = walk_repository(root, cfg)
    # Filter scanned files to only changed files
    diff_files = [f for f in walk_res.files if f.path in changed_files]

    manifest_deps = []
    for fe in walk_res.files:
        if fe.path.lower().split("/")[-1] in MANIFEST_NAMES and fe.path in changed_files:
            manifest_deps.extend(parse_manifest(root / fe.path, fe.path))

    context = ScanContext(root, diff_files, manifest_deps, cfg)
    raw_findings = registry.run_all(context)
    deduped = deduplicate_findings(raw_findings)
    suppressed = apply_suppressions(deduped, context)

    score, grade, breakdown = compute_repo_truth_score(suppressed)
    active = [f for f in suppressed if not f.suppressed]

    return {
        "changed_files": changed_files[:20],
        "changed_files_count": len(changed_files),
        "findings_count": len(active),
        "score": score,
        "grade": grade,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "location": f"{f.location.path}:{f.location.start_line}",
                "message": f.message,
                "fix_hint": f.fix_hint,
            }
            for f in active[:15]
        ],
    }


@server.tool()
def check_done(
    task_summary: str,
    changed_files: Optional[list[str]] = None,
    path: str = ".",
) -> dict[str, Any]:
    """Inspect changes against HEAD and return whether a task can be marked done."""
    root = _resolve_safe_path(path, Path(".").resolve())
    files_to_check = (
        set(changed_files) if changed_files else set(_get_git_changed_files(root, "HEAD"))
    )

    cfg = PlumblineConfig()
    walk_res = walk_repository(root, cfg)
    target_files = (
        [f for f in walk_res.files if f.path in files_to_check]
        if files_to_check
        else walk_res.files
    )

    manifest_deps = []
    for fe in walk_res.files:
        if fe.path.lower().split("/")[-1] in MANIFEST_NAMES:
            manifest_deps.extend(parse_manifest(root / fe.path, fe.path))

    context = ScanContext(root, target_files, manifest_deps, cfg)
    raw_findings = registry.run_all(context)
    deduped = deduplicate_findings(raw_findings)
    active = apply_suppressions(deduped, context)

    # Check for blocking issues:
    # 1. Any Critical or High finding
    # 2. Any new GAP002 (stub body), SLP002 (synthetic test data in prod), or CLM004 (literal return)
    blockers: list[str] = []
    for fnd in active:
        if fnd.suppressed:
            continue
        if fnd.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
            blockers.append(
                f"[{fnd.severity.value.upper()}] {fnd.rule_id} in {fnd.location.path}:{fnd.location.start_line} - {fnd.message}"
            )
        elif fnd.rule_id in ("GAP002", "SLP002", "CLM004"):
            blockers.append(
                f"[{fnd.rule_id}] Unfinished code in {fnd.location.path}:{fnd.location.start_line} - {fnd.message}"
            )

    # Check claim verifications
    raw_claims = extract_claims(context)
    verified = verify_all_claims(raw_claims, context, findings=raw_findings)
    unverified_claims = [
        f"Claim '{c.text}' ({c.claim_type}) in {c.source.path}:{c.source.start_line} is {c.verdict.value}"
        for c in verified
        if c.verdict in (ClaimVerdict.UNSUPPORTED, ClaimVerdict.CONTRADICTED)
    ]

    is_done = len(blockers) == 0

    next_steps: list[str] = []
    if not is_done:
        next_steps.append(f"Resolve {len(blockers)} blocking issues before finishing.")
        if any("GAP002" in b for b in blockers):
            next_steps.append(
                "Replace stub bodies (pass, NotImplementedError) with real implementations."
            )
        if any("SLP002" in b for b in blockers):
            next_steps.append(
                "Replace synthetic test data constants in production files with production configuration."
            )
        if any("CLM004" in b for b in blockers):
            next_steps.append(
                "Ensure functions consume their declared parameters instead of returning static literals."
            )
    else:
        next_steps.append("All truth and security checks pass. Changes are ready to commit.")

    return {
        "done": is_done,
        "task_summary": task_summary,
        "blockers": blockers[:10],
        "unverified_claims": unverified_claims[:5],
        "next_steps": next_steps,
    }


@server.tool()
def explain_rule(rule_id: str) -> dict[str, Any]:
    """Retrieve detailed specification and guidance for a detection rule."""
    spec = registry.get(rule_id.upper())
    if not spec:
        return {"error": f"Rule ID '{rule_id}' not found in registry."}

    return {
        "id": spec.id,
        "title": spec.title,
        "family": spec.family,
        "severity": spec.severity.value,
        "confidence": spec.confidence.value,
        "heuristic": spec.heuristic,
        "tags": spec.tags,
        "fix_hint": spec.fix_hint,
        "bad_example": spec.bad,
        "good_example": spec.good,
        "suppression": f"// plumbline:ignore[{spec.id}] <mandatory reason>",
    }


def run_mcp_server() -> None:
    """Run standard stdio MCP server."""
    server.run(transport="stdio")

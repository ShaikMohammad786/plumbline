"""Safe auto-fix patch generation and application for SEC005, SLP007, and DEP005."""

from __future__ import annotations

import difflib
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from plumbline.models import Finding

SAFE_AUTOFIX_RULES = {"SEC005", "SLP007", "DEP005"}


def generate_patch_for_finding(finding: Finding, root: Path) -> Optional[tuple[str, str, str]]:
    """Generate a unified diff patch for a safe autofix finding.

    Returns (relative_path, unified_diff_text, new_file_content) or None.
    """
    if finding.rule_id not in SAFE_AUTOFIX_RULES:
        return None

    rel_path = finding.location.path
    file_path = root / rel_path
    if not file_path.is_file():
        return None

    try:
        old_content = file_path.read_text(encoding="utf-8")
    except Exception:
        return None

    old_lines = old_content.splitlines(keepends=True)
    new_lines = list(old_lines)
    line_idx = finding.location.start_line - 1

    if finding.rule_id == "SEC005":
        if line_idx < 0 or line_idx >= len(new_lines):
            return None
        orig_line = new_lines[line_idx]
        modified = orig_line
        modified = re.sub(r"\bverify\s*=\s*False\b", "verify=True", modified)
        modified = re.sub(
            r"\brejectUnauthorized\s*:\s*false\b",
            "rejectUnauthorized: true",
            modified,
            flags=re.IGNORECASE,
        )
        modified = re.sub(
            r"\bInsecureSkipVerify\s*:\s*true\b",
            "InsecureSkipVerify: false",
            modified,
            flags=re.IGNORECASE,
        )
        if modified == orig_line:
            return None
        new_lines[line_idx] = modified

    elif finding.rule_id == "SLP007":
        if line_idx < 0 or line_idx >= len(new_lines):
            return None
        # Remove debug leftover line
        new_lines.pop(line_idx)

    elif finding.rule_id == "DEP005":
        # Extract unused dependency name from message or evidence
        # e.g., "Declared dependency 'foo' is never imported"
        dep_match = re.search(r"['\"]([a-zA-Z0-9_\-\.]+)['\"]", finding.message)
        dep_name = dep_match.group(1).lower() if dep_match else ""
        if not dep_name:
            return None

        if "package.json" in rel_path:
            try:
                pkg_data = json.loads(old_content)
                changed = False
                for sec in ("dependencies", "devDependencies"):
                    if sec in pkg_data and dep_name in pkg_data[sec]:
                        del pkg_data[sec][dep_name]
                        changed = True
                if not changed:
                    return None
                new_content = json.dumps(pkg_data, indent=2) + "\n"
                new_lines = new_content.splitlines(keepends=True)
            except Exception:
                return None
        else:
            # Requirements file
            filtered = []
            removed = False
            for line in old_lines:
                clean_line = line.strip().split(";")[0].split("#")[0].strip()
                pkg_match = re.match(r"^([a-zA-Z0-9_\-\.]+)", clean_line)
                if pkg_match and pkg_match.group(1).lower().replace("_", "-") == dep_name.replace(
                    "_", "-"
                ):
                    removed = True
                    continue
                filtered.append(line)
            if not removed:
                return None
            new_lines = filtered

    new_content = "".join(new_lines)
    if new_content == old_content:
        return None

    diff = "".join(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}",
        )
    )
    return (rel_path, diff, new_content)


def generate_and_save_patches(
    findings: list[Finding],
    root: Path,
    out_dir: Path = Path(".plumbline/fixes"),
) -> list[tuple[Finding, str, Path]]:
    """Generate patches for all eligible safe autofix findings and save to disk."""
    out_dir.mkdir(parents=True, exist_ok=True)
    generated: list[tuple[Finding, str, Path]] = []

    for f in findings:
        res = generate_patch_for_finding(f, root)
        if not res:
            continue
        rel_path, diff, _ = res
        patch_file = out_dir / f"{f.id}.patch"
        try:
            patch_file.write_text(diff, encoding="utf-8")
            f.fix_patch = diff
            generated.append((f, diff, patch_file))
        except Exception:
            continue

    return generated


def apply_patch_to_disk(finding: Finding, root: Path) -> bool:
    """Apply an eligible finding's safe autofix to disk."""
    res = generate_patch_for_finding(finding, root)
    if not res:
        return False
    rel_path, _, new_content = res
    file_path = root / rel_path
    try:
        file_path.write_text(new_content, encoding="utf-8")
        return True
    except Exception:
        return False

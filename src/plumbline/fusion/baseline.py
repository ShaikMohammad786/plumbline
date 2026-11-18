"""Baseline finding persistence and matching."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from plumbline.models import Finding

DEFAULT_BASELINE_FILE = Path(".plumbline/baseline.json")


def load_baseline(baseline_path: Optional[Path] = None) -> set[str]:
    """Load set of fingerprinted finding IDs from baseline file."""
    path = baseline_path or DEFAULT_BASELINE_FILE
    if not path.exists():
        return set()

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return set(data.get("fingerprints", []))
        if isinstance(data, list):
            return set(data)
    except Exception:
        # plumbline:ignore[SLP001] Missing or malformed baseline file defaults to empty set
        pass
    return set()


def save_baseline(findings: list[Finding], baseline_path: Optional[Path] = None) -> int:
    """Save active finding fingerprints into baseline file."""
    path = baseline_path or DEFAULT_BASELINE_FILE
    path.parent.mkdir(parents=True, exist_ok=True)

    fingerprints = sorted(list({f.id for f in findings if not f.suppressed}))
    data = {
        "version": 1,
        "count": len(fingerprints),
        "fingerprints": fingerprints,
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return len(fingerprints)


def apply_baseline(findings: list[Finding], baseline_path: Optional[Path] = None) -> list[Finding]:
    """Mark findings present in baseline as baselined=True."""
    baseline_fps = load_baseline(baseline_path)
    if not baseline_fps:
        return findings

    for f in findings:
        if f.id in baseline_fps:
            f.baselined = True

    return findings

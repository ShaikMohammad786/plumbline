"""Stable finding fingerprinting across line shifts."""

from __future__ import annotations

import hashlib
from pathlib import PurePath


def normalize_snippet(snippet: str) -> str:
    """Normalize code snippet by trimming lines and removing blanks."""
    lines = [line.strip() for line in snippet.splitlines() if line.strip()]
    return "\n".join(lines)


def compute_fingerprint(rule_id: str, snippet: str, relative_path: str) -> str:
    """Compute stable 16-hex fingerprint: sha256(rule_id + normalized_snippet + relative_posix_path)[:16]."""
    posix_path = PurePath(relative_path).as_posix()
    normalized = normalize_snippet(snippet)
    payload = f"{rule_id}:{normalized}:{posix_path}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]

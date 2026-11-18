"""Finding deduplication."""

from __future__ import annotations

from plumbline.models import Finding


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings based on ID (fingerprint) or (rule_id, path, start_line)."""
    seen_ids: set[str] = set()
    seen_locs: set[tuple[str, str, int]] = set()
    unique: list[Finding] = []

    for f in findings:
        loc_key = (f.rule_id, f.location.path, f.location.start_line)
        if f.id in seen_ids or loc_key in seen_locs:
            continue
        seen_ids.add(f.id)
        seen_locs.add(loc_key)
        unique.append(f)

    return unique

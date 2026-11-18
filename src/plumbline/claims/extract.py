"""Claim extraction engine parsing documentation for checkable assertions."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

import yaml

if TYPE_CHECKING:
    from plumbline.detectors.context import ScanContext
from plumbline.models import Claim, ClaimVerdict, FindingConfidence, Location

TAXONOMY_PATH = Path(__file__).parent / "taxonomy.yml"
_TAXONOMY_CACHE: Optional[dict[str, Any]] = None


def load_taxonomy() -> dict[str, Any]:
    """Load and cache the 20-category capability taxonomy."""
    global _TAXONOMY_CACHE
    if _TAXONOMY_CACHE is not None:
        return _TAXONOMY_CACHE
    if not TAXONOMY_PATH.exists():
        return {}
    with open(TAXONOMY_PATH, encoding="utf-8") as f:
        _TAXONOMY_CACHE = yaml.safe_load(f) or {}
    return _TAXONOMY_CACHE


def _clean_markdown_line(line: str) -> str:
    """Strip markdown formatting from line."""
    cleaned = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", line)  # links
    cleaned = re.sub(r"[*_`~]", "", cleaned)  # styling
    cleaned = re.sub(r"^#+\s*", "", cleaned)  # headings
    cleaned = re.sub(r"^[-*+]\s*", "", cleaned)  # list items
    cleaned = re.sub(r"^\d+\.\s*", "", cleaned)  # numbered lists
    return cleaned.strip()


def extract_claims(context: ScanContext) -> list[Claim]:
    """Extract checkable capability claims from README, docs, AI_LOG, and manifests."""
    taxonomy = load_taxonomy()
    if not taxonomy:
        return []

    # Compile trigger regexes per category
    compiled_triggers: dict[str, list[re.Pattern[str]]] = {}
    for cat, data in taxonomy.items():
        patterns = data.get("triggers", [])
        compiled_triggers[cat] = [re.compile(p, re.IGNORECASE) for p in patterns]

    claims: list[Claim] = []
    seen_texts: set[str] = set()

    # Documentation files to scan
    target_files = []
    for f in context.files:
        name_lower = f.path.lower()
        if (
            name_lower.endswith(".md")
            or "readme" in name_lower
            or "ai_log" in name_lower
            or name_lower.startswith("docs/")
        ):
            # Skip generated rule docs, scoring docs, or testing fixtures
            if (
                "tests/" in f.path
                or "bench/" in f.path
                or "rules.md" in name_lower
                or "scoring.md" in name_lower
                or "brief.md" in name_lower
                or "demo_script" in name_lower
                or "demo/" in name_lower
            ):
                continue
            target_files.append(f)

    for f in target_files:
        lines = context.get_lines(f.path)
        in_code_block = False

        for line_no, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if stripped.startswith("```"):
                in_code_block = not in_code_block
                continue
            if in_code_block or not stripped:
                continue
            if stripped.startswith("|") and stripped.endswith("|"):
                continue

            cleaned = _clean_markdown_line(stripped)
            if len(cleaned) < 10 or len(cleaned) > 280:
                continue

            # Split into individual sentences if multiple
            sentences = [
                s.strip() for s in re.split(r"(?<=[.!?])\s+", cleaned) if len(s.strip()) >= 10
            ]
            if not sentences:
                sentences = [cleaned]

            for sentence in sentences:
                norm_sentence = sentence.lower()
                if norm_sentence in seen_texts:
                    continue
                if any(
                    neg in norm_sentence
                    for neg in (
                        "false-positive",
                        "removed",
                        "rejected",
                        "rejection",
                        "fixed",
                        "instead of",
                        "discrepanc",
                    )
                ):
                    continue

                for cat, patterns in compiled_triggers.items():
                    if any(p.search(sentence) for p in patterns):
                        claim_id = hashlib.sha256(
                            f"{cat}:{sentence}:{f.path}".encode()
                        ).hexdigest()[:16]
                        seen_texts.add(norm_sentence)
                        claims.append(
                            Claim(
                                id=claim_id,
                                text=sentence,
                                source=Location(path=f.path, start_line=line_no, end_line=line_no),
                                claim_type=cat,
                                verdict=ClaimVerdict.UNCHECKED,
                                confidence=FindingConfidence.HIGH,
                                method="rule",
                            )
                        )
                        break

    return claims

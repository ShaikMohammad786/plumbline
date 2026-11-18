"""Secret detection, Shannon entropy, and non-negotiable masking utilities."""

from __future__ import annotations

import math
import re
from typing import Optional

KNOWN_SECRET_PATTERNS = [
    # AWS Access Key
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "AWS Access Key ID"),
    # GitHub Token
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"), "GitHub Token"),
    # Stripe Secret Key (live or test mode)
    (re.compile(r"\b(sk_(?:live|test)_[0-9a-zA-Z]{24,})\b"), "Stripe Secret Key"),
    # Slack Token
    (re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"), "Slack Token"),
    # Private Key Header
    (
        re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)"),
        "Private Cryptographic Key",
    ),
]

SECRET_ASSIGN_RE = re.compile(
    r"""(?i)\b(api[_-]?key|secret[_-]?key|password|auth[_-]?token|access[_-]?token)\s*[:=]\s*['"]([A-Za-z0-9+/=_\-]{16,})['"]"""
)


def mask_secret(value: str) -> str:
    """Mask secret value: first 4 characters followed by asterisks (Rule 3)."""
    if len(value) <= 4:
        return "****"
    mask_len = min(20, max(4, len(value) - 4))
    return value[:4] + "*" * mask_len


def mask_evidence_snippet(snippet: str, secret_value: str) -> str:
    """Ensure raw secret value never appears unmasked inside code evidence snippets."""
    if not secret_value:
        return snippet
    masked = mask_secret(secret_value)
    return snippet.replace(secret_value, masked)


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy for character distribution."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {c: data.count(c) for c in set(data)}
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def find_secret_in_line(line: str) -> Optional[tuple[str, str, str]]:
    """Scan line for known patterns or high-entropy assignments.

    Returns (masked_line, secret_type, raw_secret_for_internal_redaction).
    """
    # 1. Known formats
    for pattern, secret_type in KNOWN_SECRET_PATTERNS:
        m = pattern.search(line)
        if m:
            raw_val = m.group(1)
            # Skip placeholders and tests
            lower = raw_val.lower()
            if any(p in lower for p in ("example", "dummy", "placeholder", "xxx", "00000")):
                continue
            masked_line = mask_evidence_snippet(line, raw_val)
            return masked_line, secret_type, raw_val

    # 2. Variable assignments with entropy check
    assign_match = SECRET_ASSIGN_RE.search(line)
    if assign_match:
        var_name = assign_match.group(1)
        raw_val = assign_match.group(2)
        lower = raw_val.lower()
        if any(p in lower for p in ("example", "dummy", "placeholder", "changeme", "test")):
            return None

        # Check entropy on candidate value
        entropy = calculate_shannon_entropy(raw_val)
        if entropy >= 4.0 or len(raw_val) >= 32:
            masked_line = mask_evidence_snippet(line, raw_val)
            return masked_line, f"Hardcoded credential ({var_name})", raw_val

    return None

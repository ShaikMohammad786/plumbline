"""Secret redaction and untrusted code encapsulation for LLM safety."""

from __future__ import annotations

import re

# Regex patterns matching common secret formats
SECRET_PATTERNS = [
    # AWS Access Key ID
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    # GitHub Tokens
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"),
    # Generic API Keys / Bearer Tokens / Stripe
    re.compile(r"\b(sk_[live|test]_[0-9a-zA-Z]{24,})\b"),
    re.compile(r"\b(bearer\s+[A-Za-z0-9_\-\.]{20,})\b", re.IGNORECASE),
    re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
    # Private Key blocks
    re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),
    # Key assignment patterns: api_key = "..."
    re.compile(
        r"""(?i)\b(api_key|apikey|secret|token|password|auth_token|access_token|private_key)\s*[:=]\s*['"]([^'"]{8,})['"]"""
    ),
]


def mask_secret_value(value: str) -> str:
    """Mask a secret value showing only the first 4 chars followed by asterisks."""
    if len(value) <= 4:
        return "****"
    visible = value[:4]
    masked = "*" * min(max(len(value) - 4, 4), 24)
    return f"{visible}{masked}"


def redact_secrets(text: str) -> str:
    """Redact known secrets and sensitive patterns from text before model transmission."""
    if not text:
        return text

    redacted = text

    # Handle private key blocks
    redacted = re.sub(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "[REDACTED_PRIVATE_KEY_BLOCK]",
        redacted,
    )

    # Handle explicit key-value assignments
    def _mask_assignment(match: re.Match[str]) -> str:
        key_name = match.group(1)
        secret_val = match.group(2)
        masked_val = mask_secret_value(secret_val)
        return f'{key_name}="{masked_val}"'

    redacted = re.sub(
        r"""(?i)\b(api_key|apikey|secret|token|password|auth_token|access_token|private_key)\s*[:=]\s*['"]([^'"]{8,})['"]""",
        _mask_assignment,
        redacted,
    )

    # Handle standard token patterns
    for pat in SECRET_PATTERNS[:5]:

        def _mask_match(m: re.Match[str]) -> str:
            token = m.group(1)
            return mask_secret_value(token)

        redacted = pat.sub(_mask_match, redacted)

    return redacted


def wrap_untrusted(code: str) -> str:
    """Wrap scanned code in safety boundaries and redact any embedded secrets."""
    sanitized = redact_secrets(code)
    return f"<untrusted_code>\n{sanitized}\n</untrusted_code>"

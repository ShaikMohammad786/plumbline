"""Language and format detection for repository files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

EXTENSION_MAP: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".h": "c_header",
    ".hpp": "cpp_header",
    ".sh": "bash",
    ".bash": "bash",
    ".zsh": "bash",
    ".sql": "sql",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".md": "markdown",
    ".tf": "terraform",
}

FILENAME_MAP: dict[str, str] = {
    "dockerfile": "dockerfile",
    "containerfile": "dockerfile",
    "makefile": "make",
    "gemfile": "ruby",
    "pipfile": "toml",
}

SHEBANG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^#!\s*/usr/bin/env\s+python[0-9.]*"), "python"),
    (re.compile(r"^#!\s*/usr/bin/python[0-9.]*"), "python"),
    (re.compile(r"^#!\s*/usr/bin/env\s+node"), "javascript"),
    (re.compile(r"^#!\s*/usr/bin/env\s+bash"), "bash"),
    (re.compile(r"^#!\s*/bin/bash"), "bash"),
    (re.compile(r"^#!\s*/bin/sh"), "bash"),
    (re.compile(r"^#!\s*/usr/bin/env\s+ruby"), "ruby"),
    (re.compile(r"^#!\s*/usr/bin/env\s+php"), "php"),
]


def detect_language(path: Path, first_line: Optional[str] = None) -> Optional[str]:
    """Detect language by extension, exact filename, or shebang."""
    name_lower = path.name.lower()
    if name_lower in FILENAME_MAP:
        return FILENAME_MAP[name_lower]

    ext = path.suffix.lower()
    if ext in EXTENSION_MAP:
        return EXTENSION_MAP[ext]

    if first_line and first_line.startswith("#!"):
        for pattern, lang in SHEBANG_PATTERNS:
            if pattern.search(first_line):
                return lang

    return None

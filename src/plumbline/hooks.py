"""Git hooks installer and manager for Plumbline."""

from __future__ import annotations

import stat
from pathlib import Path


def install_git_hook(repo_root: Path = Path(".")) -> Path:
    """Install git pre-commit hook that executes 'plumb gate'."""
    resolved_root = repo_root.resolve()
    git_dir = resolved_root / ".git"
    if not git_dir.is_dir():
        raise FileNotFoundError(f"Not a git repository: {git_dir} does not exist.")

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    script_content = (
        "#!/bin/sh\n"
        "# Plumbline pre-commit gate hook\n"
        "# Run fast staged scan and block commit on high/critical findings\n"
        "if command -v plumb >/dev/null 2>&1; then\n"
        "    plumb gate\n"
        "elif [ -f './.venv/Scripts/plumb.exe' ]; then\n"
        "    ./.venv/Scripts/plumb.exe gate\n"
        "elif [ -f './.venv/bin/plumb' ]; then\n"
        "    ./.venv/bin/plumb gate\n"
        "elif [ -f './.venv/Scripts/python.exe' ]; then\n"
        "    ./.venv/Scripts/python.exe -m plumbline.cli gate\n"
        "elif [ -f './.venv/bin/python' ]; then\n"
        "    ./.venv/bin/python -m plumbline.cli gate\n"
        "else\n"
        "    python -m plumbline.cli gate\n"
        "fi\n"
        "exit $?\n"
    )

    hook_path.write_text(script_content, encoding="utf-8")

    # Mark as executable on Unix / POSIX
    try:
        current_mode = hook_path.stat().st_mode
        hook_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass

    return hook_path

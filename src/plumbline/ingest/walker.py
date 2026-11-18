"""Directory walker for Plumbline respecting .gitignore, binary checks, and size limits."""

from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Optional

import pathspec

from plumbline.config import PlumblineConfig
from plumbline.ingest.classify import classify_file
from plumbline.ingest.languages import detect_language
from plumbline.models import FileClass

DEFAULT_EXCLUDES = [
    ".git",
    ".git/*",
    "node_modules",
    "node_modules/*",
    "venv",
    "venv/*",
    ".venv",
    ".venv/*",
    "dist",
    "dist/*",
    "build",
    "build/*",
    "target",
    "target/*",
    "__pycache__",
    "__pycache__/*",
    ".plumbline",
    ".plumbline/*",
]


@dataclass
class FileEntry:
    path: str  # posix relative to root
    full_path: Path
    size: int
    language: Optional[str]
    file_class: FileClass
    text_hash: str
    text: Optional[str] = None


@dataclass
class WalkResult:
    files: list[FileEntry]
    notes: list[str]


def _process_candidate_file(
    file_info: tuple[Path, str, int],
    max_bytes: int,
    max_file_kb: int,
    class_overrides: Optional[dict[str, str]],
) -> tuple[Optional[FileEntry], Optional[str]]:
    file_path, rel_file, file_size = file_info

    if file_size > max_bytes:
        return (
            None,
            f"Skipped {rel_file}: size ({file_size // 1024} KB) exceeds limit ({max_file_kb} KB)",
        )

    try:
        raw_bytes = file_path.read_bytes()
    except Exception:
        return None, None

    # Binary sniff: null byte in first 8192 bytes
    if b"\x00" in raw_bytes[:8192]:
        return None, None

    content = raw_bytes.decode("utf-8", errors="replace")
    first_line = content.splitlines()[0] if content else None
    lang = detect_language(file_path, first_line)

    sample_lines = "\n".join(content.splitlines()[:5])
    file_class = classify_file(
        rel_file,
        first_lines=sample_lines,
        class_overrides=class_overrides,
    )

    text_hash = hashlib.sha256(raw_bytes).hexdigest()

    return (
        FileEntry(
            path=rel_file,
            full_path=file_path,
            size=file_size,
            language=lang,
            file_class=file_class,
            text_hash=text_hash,
            text=content,
        ),
        None,
    )


def walk_repository(root_path: Path, config: PlumblineConfig) -> WalkResult:
    """Walk the repository files honoring .gitignore, excludes, and limits."""
    resolved_root = root_path.resolve()
    files: list[FileEntry] = []
    notes: list[str] = []

    # Assemble gitignore lines
    ignore_lines: list[str] = list(DEFAULT_EXCLUDES)

    # User configured excludes
    if config.scan.exclude:
        ignore_lines.extend(config.scan.exclude)

    # Read .gitignore if present in root
    gitignore_file = resolved_root / ".gitignore"
    if gitignore_file.exists():
        try:
            with open(gitignore_file, "r", encoding="utf-8", errors="replace") as f:
                ignore_lines.extend(f.readlines())
        except Exception:
            pass

    spec = pathspec.PathSpec.from_lines("gitignore", ignore_lines)

    # Inclusions override
    include_spec: Optional[pathspec.PathSpec[Any]] = None
    if config.scan.include:
        include_spec = pathspec.PathSpec.from_lines("gitignore", config.scan.include)

    visited_realpaths: set[str] = set()
    max_bytes = config.scan.max_file_kb * 1024

    candidates: list[tuple[Path, str, int]] = []

    for root, dirs, filenames in os.walk(resolved_root, followlinks=False):
        # Symlink loop guard
        try:
            real_dir = os.path.realpath(root)
            if real_dir in visited_realpaths:
                dirs.clear()
                continue
            visited_realpaths.add(real_dir)
        except OSError:
            continue

        rel_dir = os.path.relpath(root, resolved_root)
        posix_rel_dir = "" if rel_dir == "." else PurePosixPath(rel_dir).as_posix()

        # Prune excluded directories
        pruned_dirs: list[str] = []
        for d in list(dirs):
            dir_posix = f"{posix_rel_dir}/{d}" if posix_rel_dir else d
            # Do not prune if covered by include_spec
            if include_spec and include_spec.match_file(dir_posix):
                continue
            if spec.match_file(dir_posix) or spec.match_file(f"{dir_posix}/"):
                pruned_dirs.append(d)
        for d in pruned_dirs:
            dirs.remove(d)

        for filename in filenames:
            rel_file = f"{posix_rel_dir}/{filename}" if posix_rel_dir else filename
            file_path = Path(root) / filename

            # Check ignore spec unless include_spec matches
            is_included = include_spec and include_spec.match_file(rel_file)
            if not is_included and spec.match_file(rel_file):
                continue

            try:
                stat = file_path.stat()
            except OSError:
                continue

            candidates.append((file_path, rel_file, stat.st_size))

    # Process candidates concurrently if count is significant, else sequential
    workers = min(32, (os.cpu_count() or 4) * 4)
    if len(candidates) > 50:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = executor.map(
                lambda c: _process_candidate_file(
                    c, max_bytes, config.scan.max_file_kb, config.scan.class_overrides
                ),
                candidates,
            )
            for entry, note in results:
                if entry:
                    files.append(entry)
                if note:
                    notes.append(note)
    else:
        for c in candidates:
            entry, note = _process_candidate_file(
                c, max_bytes, config.scan.max_file_kb, config.scan.class_overrides
            )
            if entry:
                files.append(entry)
            if note:
                notes.append(note)

    return WalkResult(files=files, notes=notes)

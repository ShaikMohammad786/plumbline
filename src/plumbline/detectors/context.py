"""ScanContext providing repo facts and lookup helpers to detectors."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from plumbline.config import PlumblineConfig
from plumbline.ingest.manifests import Dependency
from plumbline.ingest.walker import FileEntry
from plumbline.models import FileClass
from plumbline.ucm.builder import extract_file_facts
from plumbline.ucm.facts import UCMFileFacts


class ScanContext:
    """Read-only context passed to all rule detectors."""

    def __init__(
        self,
        root: Path,
        files: list[FileEntry],
        dependencies: list[Dependency],
        config: PlumblineConfig,
    ) -> None:
        self.root = root
        self.files = files
        self.dependencies = dependencies
        self.config = config
        self.file_map: dict[str, FileEntry] = {f.path: f for f in files}
        self._facts_cache: dict[str, UCMFileFacts] = {}
        self._lines_cache: dict[str, list[str]] = {}

    def get_facts(self, path: str) -> Optional[UCMFileFacts]:
        """Get or lazily extract UCM facts for a file."""
        if path in self._facts_cache:
            return self._facts_cache[path]

        entry = self.file_map.get(path)
        if not entry or not entry.text:
            return None

        facts = extract_file_facts(entry.path, entry.language, entry.text)
        self._facts_cache[path] = facts
        return facts

    def all_facts(self) -> dict[str, UCMFileFacts]:
        """Preload and return UCM facts for all scanned files."""
        for f in self.files:
            if f.text and f.path not in self._facts_cache:
                self.get_facts(f.path)
        return self._facts_cache

    def get_lines(self, path: str) -> list[str]:
        """Get lines of text for a file."""
        if path in self._lines_cache:
            return self._lines_cache[path]

        entry = self.file_map.get(path)
        if not entry or not entry.text:
            return []

        lines = entry.text.splitlines()
        self._lines_cache[path] = lines
        return lines

    def get_text(self, path: str) -> str:
        """Get the full content string of a file."""
        entry = self.file_map.get(path)
        return entry.text if entry and entry.text else ""

    def is_prod(self, path: str) -> bool:
        """Check if a file is classified as production code."""
        entry = self.file_map.get(path)
        return entry.file_class == FileClass.PROD if entry else False

    def find_references(self, symbol_name: str) -> list[tuple[str, int]]:
        """Find calls, imports, or identifiers matching a symbol across all files."""
        refs: list[tuple[str, int]] = []
        for path, facts in self.all_facts().items():
            # Check call sites
            for call in facts.call_sites:
                if call.callee == symbol_name or call.callee.endswith(f".{symbol_name}"):
                    refs.append((path, call.line))
            # Check imports
            for imp in facts.imports:
                if imp.name == symbol_name or imp.module == symbol_name:
                    refs.append((path, imp.line))
        return refs

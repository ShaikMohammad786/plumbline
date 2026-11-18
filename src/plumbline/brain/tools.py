"""Read-only sandboxed tools available to the LLM agent brain."""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from plumbline.brain.redact import wrap_untrusted

if TYPE_CHECKING:
    from plumbline.detectors.context import ScanContext


class BrainToolSet:
    """Read-only sandboxed tools strictly confined to the scan root."""

    def __init__(self, root: Path, context: ScanContext | None = None) -> None:
        self.root = root.resolve()
        self.context = context

    def _resolve_safe_path(self, rel_path: str) -> Path:
        """Resolve a relative path and verify it stays inside scan root."""
        # Normalize and strip leading slashes
        clean = Path(rel_path.strip().lstrip("/\\"))
        target = (self.root / clean).resolve()
        try:
            target.relative_to(self.root)
        except ValueError as exc:
            raise PermissionError(f"Access outside repository root is denied: {rel_path}") from exc
        return target

    def read_file(self, path: str, start: int = 1, end: int = 100) -> str:
        """Read lines start to end (inclusive) from a file inside the scan root."""
        safe_path = self._resolve_safe_path(path)
        if not safe_path.is_file():
            return f"Error: File not found: {path}"

        try:
            lines = safe_path.read_text(encoding="utf-8", errors="replace").splitlines()
            total_lines = len(lines)
            s = max(1, start)
            e = min(total_lines, end)
            if s > total_lines:
                return f"Error: start line {s} exceeds file length ({total_lines} lines)"
            selected = "\n".join(lines[s - 1 : e])
            return wrap_untrusted(selected)
        except Exception as exc:
            return f"Error reading file {path}: {exc}"

    def grep(self, pattern: str, glob: str = "*", max_matches: int = 20) -> list[dict[str, Any]]:
        """Grep for a regex pattern in files matching glob within the scan root."""
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            return [{"error": f"Invalid regex pattern: {exc}"}]

        matches: list[dict[str, Any]] = []
        for root_dir, dirs, files in os.walk(self.root):
            # Skip hidden and vendor dirs
            dirs[:] = [
                d
                for d in dirs
                if not d.startswith(".")
                and d not in ("node_modules", "vendor", "__pycache__", ".venv")
            ]
            for file_name in files:
                if not fnmatch.fnmatch(file_name, glob):
                    continue
                file_path = Path(root_dir) / file_name
                try:
                    rel_p = str(file_path.relative_to(self.root)).replace("\\", "/")
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    for i, line in enumerate(content.splitlines(), start=1):
                        if regex.search(line):
                            matches.append(
                                {
                                    "path": rel_p,
                                    "line": i,
                                    "snippet": line.strip()[:160],
                                }
                            )
                            if len(matches) >= max_matches:
                                return matches
                except Exception:
                    continue
        return matches

    def find_symbol(self, name: str) -> list[dict[str, Any]]:
        """Find symbol definitions (functions, classes, methods) by name in UCM facts."""
        results: list[dict[str, Any]] = []
        if not self.context:
            return results

        for p, facts in self.context.all_facts().items():
            for sym in facts.symbols:
                if sym.name == name or sym.name.endswith(f".{name}"):
                    results.append(
                        {
                            "name": sym.name,
                            "kind": sym.kind,
                            "path": p,
                            "start_line": sym.start_line,
                            "end_line": sym.end_line,
                        }
                    )
        return results

    def find_references(self, name: str) -> list[dict[str, Any]]:
        """Find call sites referencing a function or method name in UCM facts."""
        results: list[dict[str, Any]] = []
        if not self.context:
            return results

        for p, facts in self.context.all_facts().items():
            for cs in facts.call_sites:
                if cs.callee == name:
                    results.append(
                        {
                            "callee": cs.callee,
                            "path": p,
                            "line": cs.line,
                        }
                    )
        return results

    def list_dir(self, path: str = ".") -> list[str]:
        """List entries in a directory relative to the scan root."""
        safe_path = self._resolve_safe_path(path)
        if not safe_path.is_dir():
            return [f"Error: Directory not found: {path}"]

        entries: list[str] = []
        try:
            for item in sorted(safe_path.iterdir()):
                rel = str(item.relative_to(self.root)).replace("\\", "/")
                entries.append(f"{rel}/" if item.is_dir() else rel)
            return entries[:100]
        except Exception as exc:
            return [f"Error reading directory {path}: {exc}"]

    def execute_tool(self, name: str, args: dict[str, Any]) -> Any:
        """Dispatch tool invocation safely."""
        if name == "read_file":
            return self.read_file(
                path=str(args.get("path", "")),
                start=int(args.get("start", 1)),
                end=int(args.get("end", 100)),
            )
        elif name == "grep":
            return self.grep(
                pattern=str(args.get("pattern", "")),
                glob=str(args.get("glob", "*")),
                max_matches=int(args.get("max_matches", 20)),
            )
        elif name == "find_symbol":
            return self.find_symbol(name=str(args.get("name", "")))
        elif name == "find_references":
            return self.find_references(name=str(args.get("name", "")))
        elif name == "list_dir":
            return self.list_dir(path=str(args.get("path", ".")))
        else:
            return f"Error: Unknown tool '{name}'"

    @staticmethod
    def get_tool_definitions() -> list[dict[str, Any]]:
        """Return tool definitions conforming to the OpenAI function calling schema."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read lines from a file inside the repository.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "Relative file path."},
                            "start": {
                                "type": "integer",
                                "description": "Starting line number (1-indexed).",
                            },
                            "end": {
                                "type": "integer",
                                "description": "Ending line number (inclusive).",
                            },
                        },
                        "required": ["path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "grep",
                    "description": "Search for a regex pattern in repository files.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "pattern": {"type": "string", "description": "Regex pattern to match."},
                            "glob": {
                                "type": "string",
                                "description": "File glob pattern, e.g. '*.py' or '*'.",
                            },
                            "max_matches": {
                                "type": "integer",
                                "description": "Max results to return.",
                            },
                        },
                        "required": ["pattern"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "find_symbol",
                    "description": "Find symbol definitions (function, class, method) across the repo.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "Exact symbol name."},
                        },
                        "required": ["name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "find_references",
                    "description": "Find call sites referencing a symbol across the repo.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "Callee symbol name."},
                        },
                        "required": ["name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "list_dir",
                    "description": "List files and subdirectories at a path inside the repo.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "Relative directory path."},
                        },
                    },
                },
            },
        ]

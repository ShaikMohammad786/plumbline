"""Lexical / Regex fallback extractor for UCM facts."""

from __future__ import annotations

import hashlib
import re
from typing import Optional

from plumbline.ucm.facts import (
    CallArg,
    CallSite,
    Comment,
    EnvRead,
    Handler,
    Import,
    Route,
    StringLit,
    Symbol,
    TestCase,
    UCMFileFacts,
)


def extract_lexical_facts(path: str, language: Optional[str], content: str) -> UCMFileFacts:
    """Extract UCM facts using regex patterns across languages."""
    facts = UCMFileFacts(path=path, language=language, engine_used="lexical")
    lines = content.splitlines()

    # 1. Comments
    _extract_comments(lines, language, facts)

    # 2. String literals
    _extract_strings(lines, facts)

    # 3. Imports
    _extract_imports(lines, language, facts)

    # 4. Symbols (functions / classes)
    _extract_symbols(lines, language, facts)

    # 5. Callsites
    _extract_call_sites(lines, facts)

    # 6. Env reads
    _extract_env_reads(lines, facts)

    # 7. Handlers (Exceptions)
    _extract_handlers(lines, language, facts)

    # 8. Routes
    _extract_routes(lines, language, facts)

    # 9. Test cases
    _extract_tests(lines, language, facts)

    return facts


def _extract_comments(lines: list[str], language: Optional[str], facts: UCMFileFacts) -> None:
    in_block = False

    for line_no, raw in enumerate(lines, start=1):
        line = raw.strip()
        if in_block:
            facts.comments.append(Comment(text=line, line=line_no))
            if "*/" in line:
                in_block = False
            continue

        if "/*" in line:
            in_block = True
            facts.comments.append(Comment(text=line, line=line_no))
            if "*/" in line:
                in_block = False
            continue

        if language == "python":
            if line.startswith("#"):
                facts.comments.append(Comment(text=line.lstrip("#").strip(), line=line_no))
        elif language in (
            "javascript",
            "typescript",
            "tsx",
            "go",
            "java",
            "c",
            "cpp",
            "csharp",
            "php",
            "rust",
            "kotlin",
        ):
            if line.startswith("//"):
                facts.comments.append(Comment(text=line.lstrip("/").strip(), line=line_no))
        elif language in ("ruby", "bash", "yaml", "dockerfile", "toml"):
            if line.startswith("#"):
                facts.comments.append(Comment(text=line.lstrip("#").strip(), line=line_no))
        elif language == "sql":
            if line.startswith("--"):
                facts.comments.append(Comment(text=line.lstrip("-").strip(), line=line_no))


def _extract_strings(lines: list[str], facts: UCMFileFacts) -> None:
    str_re = re.compile(r"""(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")""")
    for line_no, raw in enumerate(lines, start=1):
        for m in str_re.finditer(raw):
            val = m.group(1) if m.group(1) is not None else m.group(2)
            if val and len(val) > 1:
                facts.strings.append(StringLit(value=val, line=line_no))


def _extract_imports(lines: list[str], language: Optional[str], facts: UCMFileFacts) -> None:
    py_import_re = re.compile(
        r"^\s*(?:from\s+([a-zA-Z0-9_.]+)\s+import\s+([a-zA-Z0-9_, *]+)|import\s+([a-zA-Z0-9_,.]+))"
    )
    js_import_re = re.compile(
        r"""(?:import\s+.*?\s+from\s+['"]([^'"]+)['"]|require\(['"]([^'"]+)['"]\))"""
    )
    go_import_re = re.compile(r"""import\s+(?:\(\s*([^)]+)\s*\)|['"]([^'"]+)['"])""")

    for line_no, raw in enumerate(lines, start=1):
        line = raw.strip()
        if language == "python":
            m = py_import_re.match(line)
            if m:
                if m.group(1):
                    mod = m.group(1)
                    names = [n.strip() for n in m.group(2).split(",") if n.strip()]
                    for name in names:
                        facts.imports.append(Import(module=mod, name=name, line=line_no))
                elif m.group(3):
                    for mod in m.group(3).split(","):
                        facts.imports.append(Import(module=mod.strip(), line=line_no))

        elif language in ("javascript", "typescript", "tsx"):
            for m in js_import_re.finditer(line):
                mod = m.group(1) or m.group(2)
                if mod:
                    facts.imports.append(Import(module=mod, line=line_no))

        elif language == "go":
            m = go_import_re.search(line)
            if m and m.group(2):
                facts.imports.append(Import(module=m.group(2), line=line_no))


def _extract_symbols(lines: list[str], language: Optional[str], facts: UCMFileFacts) -> None:
    fn_re = re.compile(r"^\s*(?:async\s+)?(?:def|function)\s+([a-zA-Z0-9_]+)\s*\((.*?)\)")
    class_re = re.compile(r"^\s*class\s+([a-zA-Z0-9_]+)")
    go_fn_re = re.compile(r"^\s*func\s+(?:\([^)]+\)\s+)?([a-zA-Z0-9_]+)\s*\((.*?)\)")

    for line_no, raw in enumerate(lines, start=1):
        line = raw.strip()
        if language in ("python", "javascript", "typescript", "tsx", "php", "ruby"):
            m = fn_re.match(line)
            if m:
                name, raw_params = m.groups()
                params = [
                    p.strip().split(":")[0].split("=")[0]
                    for p in raw_params.split(",")
                    if p.strip()
                ]
                body_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
                facts.symbols.append(
                    Symbol(
                        name=name,
                        kind="function",
                        start_line=line_no,
                        end_line=line_no,
                        params=params,
                        body_hash=body_hash,
                    )
                )
            m_cls = class_re.match(line)
            if m_cls:
                facts.symbols.append(
                    Symbol(name=m_cls.group(1), kind="class", start_line=line_no, end_line=line_no)
                )

        elif language == "go":
            m = go_fn_re.match(line)
            if m:
                name, raw_params = m.groups()
                params = [p.strip().split()[0] for p in raw_params.split(",") if p.strip()]
                facts.symbols.append(
                    Symbol(
                        name=name,
                        kind="function",
                        start_line=line_no,
                        end_line=line_no,
                        params=params,
                    )
                )


def _extract_call_sites(lines: list[str], facts: UCMFileFacts) -> None:
    call_re = re.compile(r"([a-zA-Z0-9_.]+)\s*\((.*?)\)")
    for line_no, raw in enumerate(lines, start=1):
        line = raw.strip()
        if line.startswith(("#", "//", "/*", "*")):
            continue
        for m in call_re.finditer(line):
            callee = m.group(1)
            raw_args = m.group(2)
            args: list[CallArg] = []
            if raw_args.strip():
                for arg_str in raw_args.split(","):
                    arg = arg_str.strip()
                    if (arg.startswith('"') and arg.endswith('"')) or (
                        arg.startswith("'") and arg.endswith("'")
                    ):
                        args.append(CallArg(kind="literal", value=arg[1:-1]))
                    elif re.match(r"^[a-zA-Z_][a-zA-Z0-9_.]*$", arg):
                        args.append(CallArg(kind="variable", value=arg))
                    else:
                        args.append(CallArg(kind="expression", value=arg))
            facts.call_sites.append(CallSite(callee=callee, line=line_no, args=args))


def _extract_env_reads(lines: list[str], facts: UCMFileFacts) -> None:
    env_re = re.compile(
        r"""(?:os\.environ(?:\.get)?\(['"]([^'"]+)['"]\)|os\.environ\[['"]([^'"]+)['"]\]|process\.env\.([a-zA-Z0-9_]+)|os\.Getenv\(['"]([^'"]+)['"]\))"""
    )
    for line_no, raw in enumerate(lines, start=1):
        for m in env_re.finditer(raw):
            var = m.group(1) or m.group(2) or m.group(3) or m.group(4)
            if var:
                facts.env_reads.append(EnvRead(var_name=var, line=line_no))


def _extract_handlers(lines: list[str], language: Optional[str], facts: UCMFileFacts) -> None:
    except_re = re.compile(r"^\s*except(?:\s+([a-zA-Z0-9_, ]+))?:")
    catch_inline_re = re.compile(r"\bcatch\s*(?:\([^)]+\))?\s*\{([^}]*)\}")
    catch_re = re.compile(r"\bcatch\s*(?:\([^)]+\))?")
    go_err_re = re.compile(r"^\s*if\s+err\s*!=\s*nil\s*\{")

    for line_no, raw in enumerate(lines, start=1):
        line = raw.strip()
        if language == "python" and except_re.match(line):
            m = except_re.match(line)
            types = [t.strip() for t in m.group(1).split(",")] if m and m.group(1) else []
            # Check next non-comment line for empty / pass
            next_idx = line_no
            while next_idx < len(lines) and lines[next_idx].strip().startswith(("#", "//")):
                next_idx += 1
            next_line = lines[next_idx].strip() if next_idx < len(lines) else ""
            is_empty = next_line in ("pass", "...", "return None", "return")
            facts.handlers.append(
                Handler(kind="exception", caught_types=types, empty=is_empty, line=line_no)
            )

        elif language in ("javascript", "typescript", "tsx", "java"):
            m_inline = catch_inline_re.search(line)
            if m_inline:
                body = m_inline.group(1).strip()
                is_empty = body == "" or body == ";" or "console.log" in body
                facts.handlers.append(Handler(kind="exception", empty=is_empty, line=line_no))
            elif catch_re.search(line):
                next_line = lines[line_no].strip() if line_no < len(lines) else ""
                is_empty = next_line in ("}", ";") or "console.log" in next_line
                facts.handlers.append(Handler(kind="exception", empty=is_empty, line=line_no))

        elif language == "go" and go_err_re.match(line):
            next_line = lines[line_no].strip() if line_no < len(lines) else ""
            is_empty = next_line == "}" or "_ = err" in next_line
            facts.handlers.append(Handler(kind="exception", empty=is_empty, line=line_no))


def _extract_routes(lines: list[str], language: Optional[str], facts: UCMFileFacts) -> None:
    route_re = re.compile(
        r"""(?:@(?:app|router|blueprint)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]|(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"])""",
        re.IGNORECASE,
    )
    for line_no, raw in enumerate(lines, start=1):
        m = route_re.search(raw)
        if m:
            method = (m.group(1) or m.group(3) or "GET").upper()
            path = m.group(2) or m.group(4) or "/"
            facts.routes.append(Route(path=path, method=method, handler_name="", line=line_no))


def _extract_tests(lines: list[str], language: Optional[str], facts: UCMFileFacts) -> None:
    test_re = re.compile(
        r"""(?:def\s+(test_[a-zA-Z0-9_]+)|(?:it|test)\s*\(\s*['"]([^'"]+)['"]|func\s+(Test[a-zA-Z0-9_]+))"""
    )
    for line_no, raw in enumerate(lines, start=1):
        m = test_re.search(raw)
        if m:
            name = m.group(1) or m.group(2) or m.group(3)
            facts.test_cases.append(TestCase(name=name, line=line_no, has_assertions=True))

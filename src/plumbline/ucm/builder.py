"""UCM builder picking Tree-Sitter when available, falling back to lexical analysis."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Optional

from plumbline.ucm.facts import (
    CallSite,
    Comment,
    Import,
    StringLit,
    Symbol,
    UCMFileFacts,
)
from plumbline.ucm.lexical import (
    _extract_env_reads,
    _extract_handlers,
    _extract_routes,
    _extract_tests,
    extract_lexical_facts,
)

_PARSER_CACHE: dict[str, Any] = {}
_QUERY_CACHE: dict[str, Any] = {}
_DISABLED_LANGUAGES: set[str] = set()

QUERIES_DIR = Path(__file__).parent / "queries"


def _get_tree_sitter_components(language: str) -> Optional[tuple[Any, Any]]:
    """Try to obtain (parser, query) for a given language."""
    if language in _DISABLED_LANGUAGES:
        return None

    if language in _PARSER_CACHE and language in _QUERY_CACHE:
        return _PARSER_CACHE[language], _QUERY_CACHE[language]

    query_file = QUERIES_DIR / f"{language}.scm"
    if not query_file.exists():
        _DISABLED_LANGUAGES.add(language)
        return None

    try:
        import tree_sitter_language_pack as tslp
        from tree_sitter import Parser, Query

        grammar_lang = tslp.get_language(language)
        if not grammar_lang:
            _DISABLED_LANGUAGES.add(language)
            return None

        parser = Parser(grammar_lang)
        query_text = query_file.read_text(encoding="utf-8")
        query = Query(grammar_lang, query_text)

        _PARSER_CACHE[language] = parser
        _QUERY_CACHE[language] = query
        return parser, query

    except Exception:
        _DISABLED_LANGUAGES.add(language)
        return None


def extract_file_facts(path: str, language: Optional[str], content: str) -> UCMFileFacts:
    """Extract facts using Tree-Sitter if available, else lexical fallback."""
    if not language:
        return extract_lexical_facts(path, language, content)

    components = _get_tree_sitter_components(language)
    if not components:
        return extract_lexical_facts(path, language, content)

    parser, query = components

    try:
        from tree_sitter import QueryCursor

        tree = parser.parse(content.encode("utf-8"))
        cursor = QueryCursor(query)
        matches = cursor.matches(tree.root_node)

        facts = UCMFileFacts(path=path, language=language, engine_used="tree-sitter")

        for _, match_dict in matches:
            # Check function definitions
            if "symbol.function.name" in match_dict:
                name_node = match_dict["symbol.function.name"][0]
                name_text = content.encode("utf-8")[
                    name_node.start_byte : name_node.end_byte
                ].decode("utf-8", errors="replace")

                def_node = match_dict.get("symbol.function.def", [name_node])[0]
                start_l = def_node.start_point[0] + 1
                end_l = def_node.end_point[0] + 1
                body_bytes = content.encode("utf-8")[def_node.start_byte : def_node.end_byte]
                body_hash = hashlib.sha256(body_bytes).hexdigest()[:16]

                facts.symbols.append(
                    Symbol(
                        name=name_text,
                        kind="function",
                        start_line=start_l,
                        end_line=end_l,
                        body_hash=body_hash,
                    )
                )

            elif "symbol.class.name" in match_dict:
                name_node = match_dict["symbol.class.name"][0]
                name_text = content.encode("utf-8")[
                    name_node.start_byte : name_node.end_byte
                ].decode("utf-8", errors="replace")

                def_node = match_dict.get("symbol.class.def", [name_node])[0]
                start_l = def_node.start_point[0] + 1
                end_l = def_node.end_point[0] + 1

                facts.symbols.append(
                    Symbol(
                        name=name_text,
                        kind="class",
                        start_line=start_l,
                        end_line=end_l,
                    )
                )

            for cap_name, nodes in match_dict.items():
                if cap_name in (
                    "symbol.function.name",
                    "symbol.function.def",
                    "symbol.class.name",
                    "symbol.class.def",
                ):
                    continue
                for node in nodes:
                    start_line = node.start_point[0] + 1
                    node_text = content.encode("utf-8")[node.start_byte : node.end_byte].decode(
                        "utf-8", errors="replace"
                    )

                    if cap_name in ("import.module", "import.name", "import.from_module"):
                        cleaned = node_text.strip("'\"")
                        facts.imports.append(Import(module=cleaned, line=start_line))
                    elif cap_name == "comment.text":
                        facts.comments.append(
                            Comment(text=node_text.lstrip("#/ *-").strip(), line=start_line)
                        )
                    elif cap_name == "string.lit":
                        val = node_text.strip("'\"")
                        if val and len(val) > 1:
                            facts.strings.append(StringLit(value=val, line=start_line))
                    elif cap_name == "call.callee":
                        facts.call_sites.append(CallSite(callee=node_text, line=start_line))

        # Fast heuristic checks before running regex passes
        lines = content.splitlines()
        content_lower = content.lower()

        if "except" in content_lower or "catch" in content_lower or "err" in content_lower:
            _extract_handlers(lines, language, facts)

        if "get" in content_lower or "post" in content_lower or "route" in content_lower:
            _extract_routes(lines, language, facts)

        if "env" in content_lower:
            _extract_env_reads(lines, facts)

        if "test" in content_lower or "it(" in content:
            _extract_tests(lines, language, facts)

        return facts

    except Exception:
        # Seamlessly fallback to lexical engine
        return extract_lexical_facts(path, language, content)

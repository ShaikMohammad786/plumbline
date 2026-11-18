"""Universal Code Model (UCM) facts and dataclasses."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Symbol:
    name: str
    kind: str  # function | class | method
    start_line: int
    end_line: int
    params: list[str] = field(default_factory=list)
    body_hash: str = ""


@dataclass(frozen=True)
class Import:
    module: str
    name: Optional[str] = None
    alias: Optional[str] = None
    line: int = 1
    is_relative: bool = False


@dataclass(frozen=True)
class StringLit:
    value: str
    line: int


@dataclass(frozen=True)
class Comment:
    text: str
    line: int
    is_docstring: bool = False


@dataclass(frozen=True)
class CallArg:
    kind: str  # literal | variable | expression
    value: str


@dataclass(frozen=True)
class CallSite:
    callee: str
    line: int
    args: list[CallArg] = field(default_factory=list)


@dataclass(frozen=True)
class Handler:
    kind: str  # exception
    caught_types: list[str] = field(default_factory=list)
    empty: bool = False
    returns_default: bool = False
    rethrows: bool = False
    line: int = 1


@dataclass(frozen=True)
class Route:
    path: str
    method: str
    handler_name: str
    guards: list[str] = field(default_factory=list)
    line: int = 1


@dataclass(frozen=True)
class EnvRead:
    var_name: str
    line: int


@dataclass(frozen=True)
class TestCase:
    name: str
    line: int
    has_assertions: bool = False
    is_skipped: bool = False


@dataclass
class UCMFileFacts:
    path: str
    language: Optional[str]
    symbols: list[Symbol] = field(default_factory=list)
    imports: list[Import] = field(default_factory=list)
    strings: list[StringLit] = field(default_factory=list)
    comments: list[Comment] = field(default_factory=list)
    call_sites: list[CallSite] = field(default_factory=list)
    handlers: list[Handler] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    env_reads: list[EnvRead] = field(default_factory=list)
    test_cases: list[TestCase] = field(default_factory=list)
    engine_used: str = "none"  # tree-sitter | lexical | none

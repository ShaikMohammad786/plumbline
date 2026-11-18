"""Core data models for Plumbline using Pydantic v2."""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class FileClass(str, Enum):
    PROD = "prod"
    TEST = "test"
    EXAMPLE = "example"
    DOCS = "docs"
    VENDOR = "vendor"
    GENERATED = "generated"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ClaimVerdict(str, Enum):
    VERIFIED = "VERIFIED"
    PARTIAL = "PARTIAL"
    UNSUPPORTED = "UNSUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    UNCHECKED = "UNCHECKED"


class Location(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    start_col: Optional[int] = Field(default=None, ge=1)
    end_col: Optional[int] = Field(default=None, ge=1)


class Evidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    snippet: str = Field(max_length=1000)
    note: Optional[str] = None


class LLMVerdict(BaseModel):
    verdict: str  # confirm | dismiss | downgrade
    rationale: str
    model: str
    fix_patch: Optional[str] = None


class Finding(BaseModel):
    id: str  # 16-char sha256 fingerprint
    rule_id: str
    family: str
    title: str
    message: str
    severity: FindingSeverity
    confidence: FindingConfidence
    heuristic: bool = False
    location: Location
    evidence: Evidence
    fix_hint: str
    fix_patch: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    source: str = "builtin"
    file_class: FileClass = FileClass.PROD
    llm: Optional[LLMVerdict] = None
    llm_dismissed: bool = False
    suppressed: bool = False
    baselined: bool = False


class Claim(BaseModel):
    id: str
    text: str
    source: Location
    claim_type: str
    verdict: ClaimVerdict = ClaimVerdict.UNCHECKED
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    confidence: FindingConfidence = FindingConfidence.HIGH
    method: str = "rule"  # rule | llm


class ScanStats(BaseModel):
    files: int = 0
    lines: int = 0
    languages: dict[str, int] = Field(default_factory=dict)
    file_classes: dict[str, int] = Field(default_factory=dict)
    ecosystems: dict[str, int] = Field(default_factory=dict)
    ucm_engines: dict[str, str] = Field(default_factory=dict)
    duration_s: float = 0.0


class Report(BaseModel):
    schema_version: str = Field(default="plumbline.report/1", alias="schema")
    tool_version: str = "0.1.0"
    started_at: str
    root: str
    git_commit: Optional[str] = None
    stats: ScanStats = Field(default_factory=ScanStats)
    findings: list[Finding] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)
    score: int = 100
    grade: str = "A"
    score_breakdown: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
    config_hash: Optional[str] = None

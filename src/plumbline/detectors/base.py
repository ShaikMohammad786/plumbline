"""Rule specification and detector base classes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from plumbline.models import Finding, FindingConfidence, FindingSeverity


@dataclass(frozen=True)
class RuleSpec:
    id: str  # e.g. GAP001, SLP001
    title: str
    family: str  # GAP | SLP | SEC | DEP | CLM
    severity: FindingSeverity
    confidence: FindingConfidence
    heuristic: bool = False
    tags: list[str] = field(default_factory=list)
    bad: str = ""
    good: str = ""
    fix_hint: str = ""
    safe_autofix: bool = False
    params: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.heuristic:
            # Heuristic rules never exceed medium confidence per brief Rule 6
            if self.confidence == FindingConfidence.HIGH:
                object.__setattr__(self, "confidence", FindingConfidence.MEDIUM)


DetectorFn = Callable[[Any], list[Finding]]

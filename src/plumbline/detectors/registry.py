"""Rule registry and execution engine for Plumbline."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from plumbline.detectors.base import DetectorFn, RuleSpec
from plumbline.detectors.context import ScanContext
from plumbline.models import Finding


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, RuleSpec] = {}
        self._detectors: dict[str, DetectorFn] = {}

    def register(self, spec: RuleSpec, fn: DetectorFn) -> None:
        self._rules[spec.id] = spec
        self._detectors[spec.id] = fn

    def get(self, rule_id: str) -> Optional[RuleSpec]:
        return self._rules.get(rule_id)

    def list_rules(self, family: Optional[str] = None) -> list[RuleSpec]:
        rules = list(self._rules.values())
        if family:
            rules = [r for r in rules if r.family.upper() == family.upper()]
        return sorted(rules, key=lambda r: r.id)

    def run_all(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rule_id, fn in sorted(self._detectors.items()):
            rule_cfg = context.config.rules.get(rule_id)
            if rule_cfg and not rule_cfg.enabled:
                continue

            try:
                rule_findings = fn(context)
                findings.extend(rule_findings)
            except Exception:
                # plumbline:ignore[SLP001] Fail soft with note, never crash per Rule 4
                pass

        return findings

    def generate_rules_docs(self, out_path: Optional[Path] = None) -> str:
        """Generate docs/RULES.md from all registered rules."""
        target = out_path or Path("docs/RULES.md")
        lines: list[str] = [
            "# Plumbline Detection Rules Catalog",
            "",
            "This document is automatically generated from registered detector specifications.",
            "",
            "| Rule ID | Family | Title | Severity | Confidence | Heuristic |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for r in self.list_rules():
            h_mark = "Yes (H)" if r.heuristic else "No"
            lines.append(
                f"| `{r.id}` | {r.family} | {r.title} | {r.severity.value} | {r.confidence.value} | {h_mark} |"
            )

        lines.extend(["", "---", "", "## Rule Specifications", ""])

        for r in self.list_rules():
            lines.append(f"### `{r.id}`: {r.title}")
            lines.append("")
            lines.append(f"- **Family**: {r.family}")
            lines.append(f"- **Severity**: {r.severity.value}")
            lines.append(f"- **Confidence**: {r.confidence.value}")
            lines.append(f"- **Heuristic**: {'Yes' if r.heuristic else 'No'}")
            if r.tags:
                lines.append(f"- **Tags**: {', '.join(r.tags)}")
            lines.append(f"- **Fix Hint**: {r.fix_hint}")
            lines.append("")
            lines.append("#### Bad Example")
            lines.append("```")
            lines.append(r.bad.strip())
            lines.append("```")
            lines.append("")
            lines.append("#### Good Example")
            lines.append("```")
            lines.append(r.good.strip())
            lines.append("```")
            lines.append("")
            lines.append("---")
            lines.append("")

        content = "\n".join(lines)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return content


registry = RuleRegistry()


def rule(spec: RuleSpec) -> Callable[[DetectorFn], DetectorFn]:
    """Decorator to register a detector function."""

    def decorator(fn: DetectorFn) -> DetectorFn:
        registry.register(spec, fn)
        return fn

    return decorator

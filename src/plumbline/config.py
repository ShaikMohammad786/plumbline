"""Configuration handling for Plumbline."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError


class ScanConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    max_file_kb: int = Field(default=1024, ge=1)
    class_overrides: dict[str, str] = Field(default_factory=dict)


class RuleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    severity: Optional[str] = None
    params: dict[str, Any] = Field(default_factory=dict)


class LLMConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str = "compat"
    model: str = "gpt-4o"
    api_key_env: str = "OPENAI_API_KEY"
    max_total_tokens: int = 100000
    redact: bool = True


class ClaimsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    extra_sources: list[str] = Field(default_factory=list)


class ReportConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    formats: list[str] = Field(default_factory=lambda: ["terminal"])
    out_dir: str = ".plumbline/out"


class PlumblineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    scan: ScanConfig = Field(default_factory=ScanConfig)
    rules: dict[str, RuleConfig] = Field(default_factory=dict)
    fail_on: str = "high"
    online: bool = False
    llm: LLMConfig = Field(default_factory=LLMConfig)
    claims: ClaimsConfig = Field(default_factory=ClaimsConfig)
    baseline: Optional[str] = None
    report: ReportConfig = Field(default_factory=ReportConfig)


def load_config(config_path: Optional[Path] = None, **cli_overrides: Any) -> PlumblineConfig:
    """Load configuration from file, apply env vars and CLI overrides."""
    data: dict[str, Any] = {}

    target_path = config_path or Path(".plumbline.yml")
    if target_path.exists():
        with open(target_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
            if not isinstance(raw, dict):
                raise ValueError(f"Invalid configuration format in {target_path}")
            data = raw

    # Environment variable overrides
    if "PLUMBLINE_FAIL_ON" in os.environ:
        data["fail_on"] = os.environ["PLUMBLINE_FAIL_ON"]
    if "PLUMBLINE_ONLINE" in os.environ:
        data["online"] = os.environ["PLUMBLINE_ONLINE"].lower() in ("1", "true", "yes")

    # CLI overrides
    for key, value in cli_overrides.items():
        if value is not None:
            data[key] = value

    try:
        return PlumblineConfig.model_validate(data)
    except ValidationError as e:
        messages: list[str] = []
        for err in e.errors():
            loc = ".".join(str(p) for p in err["loc"])
            messages.append(f"Configuration error at '{loc}': {err['msg']}")
        raise ValueError("\n".join(messages)) from e

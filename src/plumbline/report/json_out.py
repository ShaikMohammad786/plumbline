"""JSON report output for Plumbline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from plumbline.models import Report


def render_json_report(report: Report, out_path: Optional[Path] = None) -> str:
    """Serialize Report model to JSON string or write to file."""
    data = report.model_dump(by_alias=True)
    json_str = json.dumps(data, indent=2)

    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json_str, encoding="utf-8")

    return json_str

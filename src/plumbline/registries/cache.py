"""Disk-backed 24-hour cache for package registry lookups."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional

DEFAULT_CACHE_DIR = Path(".plumbline/cache/registries")
CACHE_TTL_SECONDS = 86400  # 24 hours


class RegistryCache:
    """Thread-safe file cache with 24-hour TTL for registry queries."""

    def __init__(self, cache_dir: Optional[Path] = None) -> None:
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR

    def _get_path(self, ecosystem: str, package_name: str) -> Path:
        # Sanitize package name for filesystem safety
        safe_name = "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in package_name)
        return self.cache_dir / ecosystem / f"{safe_name}.json"

    def get(self, ecosystem: str, package_name: str) -> Optional[dict[str, Any]]:
        """Retrieve cached metadata if file exists and is under 24 hours old."""
        path = self._get_path(ecosystem, package_name)
        if not path.exists():
            return None

        try:
            raw = path.read_text(encoding="utf-8")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                return None

            cached_at = payload.get("_cached_at", 0)
            if time.time() - cached_at > CACHE_TTL_SECONDS:
                return None  # Expired

            return payload.get("data")
        except Exception:
            # plumbline:ignore[SLP001] Cache read errors safely ignored
            return None

    def set(self, ecosystem: str, package_name: str, data: dict[str, Any]) -> None:
        """Store package metadata with current timestamp."""
        path = self._get_path(ecosystem, package_name)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "_cached_at": time.time(),
                "ecosystem": ecosystem,
                "package": package_name,
                "data": data,
            }
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            # plumbline:ignore[SLP001] Cache write errors safely ignored
            pass

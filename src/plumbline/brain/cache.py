"""Prompt and completion caching for LLM interactions."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Optional


class LLMCache:
    """Disk-backed cache for LLM queries keyed by hash in .plumbline/cache/llm."""

    def __init__(self, cache_dir: Path | str = ".plumbline/cache/llm", ttl_s: int = 86400) -> None:
        self.cache_dir = Path(cache_dir)
        self.ttl_s = ttl_s
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            # plumbline:ignore[SLP001] Fail-soft cache directory creation
            pass

    @staticmethod
    def compute_key(payload: Any) -> str:
        """Compute sha256 hash of a JSON-serializable payload."""
        dumped = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(dumped.encode("utf-8")).hexdigest()

    def get(self, key: str) -> Optional[dict[str, Any]]:
        """Retrieve cached response if not expired."""
        cache_file = self.cache_dir / f"{key}.json"
        if not cache_file.is_file():
            return None

        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            timestamp = data.get("_timestamp", 0)
            if time.time() - timestamp > self.ttl_s:
                # Expired
                return None
            result: dict[str, Any] = data.get("response", {})
            return result
        except Exception:
            # plumbline:ignore[SLP001] Fail-soft cache deserialization fallback
            return None

    def set(self, key: str, response: dict[str, Any]) -> None:
        """Store response in cache."""
        cache_file = self.cache_dir / f"{key}.json"
        try:
            data = {
                "_timestamp": time.time(),
                "response": response,
            }
            cache_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            # plumbline:ignore[SLP001] Fail-soft cache serialization fallback
            pass

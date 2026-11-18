"""RubyGems registry client with 24h cache and offline fallback."""

from __future__ import annotations

from typing import Any, Optional

import httpx

from plumbline.registries.cache import RegistryCache

RUBYGEMS_URL = "https://rubygems.org/api/v1/gems/{pkg}.json"


class RubyGemsRegistry:
    """Query RubyGems package metadata with cache and offline safety."""

    def __init__(self, cache: Optional[RegistryCache] = None, online: bool = False) -> None:
        self.cache = cache or RegistryCache()
        self.online = online

    def get_package_info(self, package_name: str) -> Optional[dict[str, Any]]:
        norm_name = package_name.lower().strip()

        cached = self.cache.get("rubygems", norm_name)
        if cached is not None:
            return cached

        if not self.online:
            return None

        try:
            resp = httpx.get(
                RUBYGEMS_URL.format(pkg=norm_name),
                timeout=4.0,
                headers={"User-Agent": "Plumbline/0.1.0"},
                follow_redirects=True,
            )
            if resp.status_code == 200:
                data = resp.json()
                meta = {
                    "exists": True,
                    "name": data.get("name", norm_name),
                    "version": data.get("version", ""),
                    "info": data.get("info", ""),
                    "source_code_uri": data.get("source_code_uri", ""),
                }
                self.cache.set("rubygems", norm_name, meta)
                return meta
            elif resp.status_code == 404:
                meta = {"exists": False, "name": norm_name}
                self.cache.set("rubygems", norm_name, meta)
                return meta
        except Exception:
            # plumbline:ignore[SLP001] Network error in registry lookup fails soft
            pass

        return None

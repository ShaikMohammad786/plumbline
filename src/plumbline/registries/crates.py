"""Crates.io registry client with 24h cache and offline fallback."""

from __future__ import annotations

from typing import Any, Optional

import httpx

from plumbline.registries.cache import RegistryCache

CRATES_URL = "https://crates.io/api/v1/crates/{pkg}"


class CratesRegistry:
    """Query crates.io package metadata with cache and offline safety."""

    def __init__(self, cache: Optional[RegistryCache] = None, online: bool = False) -> None:
        self.cache = cache or RegistryCache()
        self.online = online

    def get_package_info(self, package_name: str) -> Optional[dict[str, Any]]:
        norm_name = package_name.lower().strip()

        cached = self.cache.get("crates", norm_name)
        if cached is not None:
            return cached

        if not self.online:
            return None

        try:
            resp = httpx.get(
                CRATES_URL.format(pkg=norm_name),
                timeout=4.0,
                headers={"User-Agent": "Plumbline/0.1.0"},
                follow_redirects=True,
            )
            if resp.status_code == 200:
                data = resp.json().get("crate", {})
                meta = {
                    "exists": True,
                    "name": data.get("name", norm_name),
                    "version": data.get("max_version", ""),
                    "description": data.get("description", ""),
                    "repository": data.get("repository", ""),
                }
                self.cache.set("crates", norm_name, meta)
                return meta
            elif resp.status_code == 404:
                meta = {"exists": False, "name": norm_name}
                self.cache.set("crates", norm_name, meta)
                return meta
        except Exception:
            # plumbline:ignore[SLP001] Network error in registry lookup fails soft
            pass

        return None

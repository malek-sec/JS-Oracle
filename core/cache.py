"""Caching layer for fetched and analyzed content."""

import hashlib
import json
from pathlib import Path

from utils.logger import logger


class AnalysisCache:

    def __init__(self, cache_dir: str = ".cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get_key(self, content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()

    def get(self, content: str) -> dict | None:
        key = self.get_key(content)
        path = self.cache_dir / f"{key}.json"
        if not path.exists():
            return None
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
            logger.debug(f"Cache hit: {key[:12]}...")
            return result
        except json.JSONDecodeError:
            return None

    def set(self, content: str, result: dict) -> None:
        key = self.get_key(content)
        path = self.cache_dir / f"{key}.json"
        path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        logger.debug(f"Cache saved: {key[:12]}...")

    def clear(self) -> int:
        deleted = 0
        for f in self.cache_dir.glob("*.json"):
            f.unlink()
            deleted += 1
        return deleted


analysis_cache = AnalysisCache()

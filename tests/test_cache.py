"""Tests for the analysis cache key and round-trip."""

from core.cache import AnalysisCache


def test_get_key_is_deterministic_and_sensitive(tmp_path):
    c = AnalysisCache(cache_dir=str(tmp_path))
    base = c.get_key("code", "anthropic", "claude-opus-4-8", "v2")
    assert base == c.get_key("code", "anthropic", "claude-opus-4-8", "v2")
    # Any component change must produce a different key.
    assert base != c.get_key("code2", "anthropic", "claude-opus-4-8", "v2")
    assert base != c.get_key("code", "gemini", "claude-opus-4-8", "v2")
    assert base != c.get_key("code", "anthropic", "other-model", "v2")
    assert base != c.get_key("code", "anthropic", "claude-opus-4-8", "v1")


def test_set_then_get_roundtrips(tmp_path):
    c = AnalysisCache(cache_dir=str(tmp_path))
    payload = {"endpoints": [], "secrets": [{"type": "api_key"}]}
    assert c.get("code", "anthropic", "m", "v2") is None      # miss first
    c.set("code", "anthropic", "m", "v2", payload)
    assert c.get("code", "anthropic", "m", "v2") == payload     # hit after set


def test_corrupted_cache_file_is_treated_as_miss(tmp_path):
    c = AnalysisCache(cache_dir=str(tmp_path))
    key = c.get_key("code", "anthropic", "m", "v2")
    (tmp_path / f"{key}.json").write_text("{not json", encoding="utf-8")
    assert c.get("code", "anthropic", "m", "v2") is None


def test_clear_removes_cache_files(tmp_path):
    c = AnalysisCache(cache_dir=str(tmp_path))
    c.set("a", "anthropic", "m", "v2", {"x": 1})
    c.set("b", "anthropic", "m", "v2", {"x": 2})
    assert c.clear() == 2
    assert c.get("a", "anthropic", "m", "v2") is None

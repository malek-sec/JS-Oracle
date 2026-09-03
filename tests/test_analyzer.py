"""Tests for provider-client construction (workspace-id header wiring)."""

import core.analyzer as analyzer_mod
from core.analyzer import JSAnalyzer


class _FakeClient:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        _FakeClient.last = kwargs


def _force_anthropic(monkeypatch):
    monkeypatch.setattr(analyzer_mod, "_PROVIDER", "anthropic")
    monkeypatch.setattr(analyzer_mod.anthropic, "Anthropic", _FakeClient)


def test_workspace_id_sent_as_header(monkeypatch):
    _force_anthropic(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_WORKSPACE_ID", "wrkspc_test123")
    a = JSAnalyzer()
    headers = a.client.kwargs.get("default_headers", {})
    assert headers.get("anthropic-workspace-id") == "wrkspc_test123"
    assert a.client.kwargs.get("max_retries") == 0


def test_no_workspace_id_means_no_header(monkeypatch):
    _force_anthropic(monkeypatch)
    monkeypatch.delenv("ANTHROPIC_WORKSPACE_ID", raising=False)
    a = JSAnalyzer()
    assert "default_headers" not in a.client.kwargs

"""Tests for result merging, deduplication, and third-party filtering."""

from core.merger import ResultMerger


def _wrap(endpoints=None, secrets=None, auth=None, suspicious=None):
    return {
        "analysis_summary": {"total_findings": 0, "highest_severity": "none"},
        "endpoints": endpoints or [],
        "secrets": secrets or [],
        "auth_logic": auth or [],
        "suspicious_logic": suspicious or [],
    }


def test_merge_dedupes_endpoints_and_unions_parameters():
    m = ResultMerger()
    chunk_a = _wrap(endpoints=[
        {"path": "/api/users", "method": "GET", "parameters": ["id"],
         "body_structure": None, "evidence": "a", "confidence": "low"},
    ])
    chunk_b = _wrap(endpoints=[
        {"path": "/api/users", "method": "GET", "parameters": ["role"],
         "body_structure": None, "evidence": "longer evidence", "confidence": "high"},
    ])
    merged = m.merge([chunk_a, chunk_b])
    assert len(merged["endpoints"]) == 1
    ep = merged["endpoints"][0]
    assert ep["parameters"] == ["id", "role"]        # union, order preserved
    assert ep["confidence"] == "high"                 # higher confidence wins
    assert ep["evidence"] == "longer evidence"        # longer evidence wins


def test_merge_prefers_known_method_over_unknown():
    m = ResultMerger()
    a = _wrap(endpoints=[{"path": "/x", "method": "UNKNOWN", "parameters": [],
                          "body_structure": None, "evidence": "", "confidence": "low"}])
    b = _wrap(endpoints=[{"path": "/x", "method": "POST", "parameters": [],
                          "body_structure": None, "evidence": "", "confidence": "low"}])
    merged = m.merge([a, b])
    assert len(merged["endpoints"]) == 1
    assert merged["endpoints"][0]["method"] == "POST"


def test_summary_floors_severity_for_secrets():
    m = ResultMerger()
    merged = m.merge([_wrap(secrets=[{"type": "api_key", "value_preview": "x", "evidence": "e"}])])
    # A secret with no per-item severity must not round down to "none".
    assert merged["analysis_summary"]["highest_severity"] == "high"
    assert merged["analysis_summary"]["total_findings"] == 1


def test_filter_third_party_keeps_relative_and_subdomains_drops_others():
    m = ResultMerger()
    results = _wrap(endpoints=[
        {"path": "/api/local", "method": "GET", "parameters": [], "body_structure": None,
         "evidence": "", "confidence": "high"},
        {"path": "https://api.example.com/v1", "method": "GET", "parameters": [],
         "body_structure": None, "evidence": "", "confidence": "high"},
        {"path": "https://cdn.thirdparty.net/lib.js", "method": "GET", "parameters": [],
         "body_structure": None, "evidence": "", "confidence": "high"},
        {"path": "https://evil-example.com/x", "method": "GET", "parameters": [],
         "body_structure": None, "evidence": "", "confidence": "high"},
        {"path": "https://example.com.attacker.net/x", "method": "GET", "parameters": [],
         "body_structure": None, "evidence": "", "confidence": "high"},
    ])
    filtered = m.filter_third_party(results, "example.com")
    kept = {ep["path"] for ep in filtered["endpoints"]}
    assert kept == {"/api/local", "https://api.example.com/v1"}


def test_filter_third_party_is_case_insensitive():
    m = ResultMerger()
    results = _wrap(endpoints=[
        {"path": "https://API.Example.com/v1", "method": "GET", "parameters": [],
         "body_structure": None, "evidence": "", "confidence": "high"},
    ])
    filtered = m.filter_third_party(results, "Example.COM")
    assert len(filtered["endpoints"]) == 1


def test_filter_third_party_accepts_full_url_as_domain():
    m = ResultMerger()
    results = _wrap(endpoints=[
        {"path": "https://eservices.example.sa/api/v1", "method": "GET", "parameters": [],
         "body_structure": None, "evidence": "", "confidence": "high"},
        {"path": "https://api.eservices.example.sa/x", "method": "GET", "parameters": [],
         "body_structure": None, "evidence": "", "confidence": "high"},
        {"path": "https://cdn.other.net/x.js", "method": "GET", "parameters": [],
         "body_structure": None, "evidence": "", "confidence": "high"},
    ])
    # A full URL passed as --domain is normalized to its hostname (eservices.example.sa).
    filtered = m.filter_third_party(results, "https://eservices.example.sa/portal/")
    kept = {ep["path"] for ep in filtered["endpoints"]}
    assert kept == {"https://eservices.example.sa/api/v1", "https://api.eservices.example.sa/x"}


def test_filter_third_party_empty_target_is_noop():
    m = ResultMerger()
    results = _wrap(endpoints=[
        {"path": "https://anything.com/x", "method": "GET", "parameters": [],
         "body_structure": None, "evidence": "", "confidence": "high"},
    ])
    filtered = m.filter_third_party(results, "")
    assert len(filtered["endpoints"]) == 1

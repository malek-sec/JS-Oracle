"""Tests for the offline (no-API) pattern scans."""

from core.patterns import (
    find_endpoints,
    find_secrets,
    find_source_maps,
    is_known_library,
    offline_findings,
)


def test_find_source_maps_detects_both_comment_forms():
    js = (
        "console.log(1);\n"
        "//# sourceMappingURL=app.min.js.map\n"
        "//@ sourceMappingURL=https://cdn.example.com/vendor.js.map\n"
    )
    maps = find_source_maps(js)
    assert "app.min.js.map" in maps
    assert "https://cdn.example.com/vendor.js.map" in maps


def test_find_source_maps_deduplicates():
    js = "//# sourceMappingURL=a.map\n//# sourceMappingURL=a.map\n"
    assert find_source_maps(js) == ["a.map"]


def test_find_source_maps_none():
    assert find_source_maps("const x = 1;") == []
    assert find_source_maps("") == []


def test_offline_findings_shape():
    out = offline_findings("//# sourceMappingURL=a.map")
    assert set(out) == {"analysis_summary", "endpoints", "secrets", "auth_logic", "suspicious_logic"}
    assert len(out["suspicious_logic"]) == 1
    finding = out["suspicious_logic"][0]
    assert finding["severity"] == "info"
    assert "a.map" in finding["description"]
    # Empty input yields no findings.
    assert offline_findings("var a=1;")["suspicious_logic"] == []


def test_find_secrets_detects_known_formats_and_masks():
    secrets = find_secrets('const k="AKIAIOSFODNN7EXAMPLE"; const ip="192.168.1.1";')
    types = {s["type"] for s in secrets}
    assert "aws_key" in types
    assert "internal_ip" in types
    # Values are masked, never emitted in full via value_preview.
    aws = next(s for s in secrets if s["type"] == "aws_key")
    assert aws["value_preview"].endswith("***")
    assert aws["value_preview"] != "AKIAIOSFODNN7EXAMPLE"


def test_find_secrets_detects_expanded_formats_and_masks():
    """GitLab / npm / SendGrid / Stripe-restricted / Twilio / Google-OAuth / Slack webhook."""
    samples = [
        "glpat-ABCDabcd1234EFGH5678",
        "npm_abcdefghijklmnopqrstuvwxyz0123456789",
        "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
        "rk_live_abcdefghijklmnopqrstuvwx",
        "SK0123456789abcdef0123456789abcdef",
        "ya29.a0ARdEfGhIjKlMnOpQrStUvWx",
        "https://hooks.slack.com/services/T00000000/B11111111/abcXYZ123",
    ]
    for sample in samples:
        secrets = find_secrets(f'k = "{sample}";')
        assert secrets, f"expanded secret not detected: {sample}"
        # Never emit the raw secret value; only a masked preview.
        assert all(s["value_preview"] != sample for s in secrets), sample


def test_find_secrets_detects_jwt_and_dedupes():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk"
    secrets = find_secrets(f"a='{jwt}'; b='{jwt}';")
    jwts = [s for s in secrets if s["type"] == "jwt"]
    assert len(jwts) == 1  # deduplicated


def test_find_endpoints_extracts_urls_and_api_paths():
    js = 'fetch("https://api.example.com/v1/users"); u="/api/orders"; x="/static/app.css";'
    eps = find_endpoints(js)
    paths = {e["path"] for e in eps}
    assert "https://api.example.com/v1/users" in paths
    assert "/api/orders" in paths
    assert "/static/app.css" not in paths          # not an API-ish prefix → skipped
    assert all(e["confidence"] == "low" for e in eps)


def test_offline_findings_endpoints_are_opt_in():
    js = 'x="/api/orders"; fetch("https://a.com/api/x");'
    assert offline_findings(js, include_endpoints=False)["endpoints"] == []
    assert len(offline_findings(js, include_endpoints=True)["endpoints"]) >= 1


def test_is_known_library_matches_vendors_not_custom():
    assert is_known_library("https://x.sa/Content/js/greensock-TweenMax.min.js") is True
    assert is_known_library("https://x.sa/Scripts/jquery-3.5.1.min.js") is True
    assert is_known_library("/wp-includes/js/dist/vendor/wp-polyfill.min.js") is True
    assert is_known_library("bootstrap.min.js") is True
    # Custom / app code must NOT be treated as a library.
    assert is_known_library("https://x.sa/assets/login-913472c40d.js") is False
    assert is_known_library("https://x.sa/Content/js/238-js-custom.js") is False
    assert is_known_library("https://x.sa/assets/messages-4ed61d.js") is False
    assert is_known_library("main.js") is False

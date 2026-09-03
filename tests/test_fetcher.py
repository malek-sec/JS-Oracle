"""Tests for local file fetching, size caps, and URL validation."""

import httpx
import pytest

from core.fetcher import JSFetcher


def test_fetch_file_reads_utf8(tmp_path):
    f = tmp_path / "a.js"
    f.write_text("const x = 1;", encoding="utf-8")
    assert JSFetcher().fetch_file(str(f)) == "const x = 1;"


def test_fetch_file_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        JSFetcher().fetch_file(str(tmp_path / "nope.js"))


def test_fetch_file_rejects_oversize(tmp_path):
    f = tmp_path / "big.js"
    f.write_text("x" * 1000, encoding="utf-8")
    fetcher = JSFetcher(max_bytes=100)
    with pytest.raises(ValueError, match="too large"):
        fetcher.fetch_file(str(f))


def test_fetch_file_tolerates_non_utf8_bytes(tmp_path):
    f = tmp_path / "bad.js"
    f.write_bytes(b"var a = '\xff\xfe';")  # invalid UTF-8
    # errors="replace" means this must not raise.
    out = JSFetcher().fetch_file(str(f))
    assert "var a" in out


def test_fetch_url_rejects_bad_scheme():
    with pytest.raises(ValueError, match="Invalid URL scheme"):
        JSFetcher().fetch_url("ftp://example.com/app.js")


def test_fetch_url_wraps_tls_error_with_insecure_hint(monkeypatch):
    # A TLS/cert failure surfaces via httpx.ConnectError (there is no
    # httpx.SSLError). fetch_url must translate it to a helpful ValueError,
    # never crash with AttributeError on a non-existent attribute.
    def boom(*args, **kwargs):
        raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")

    monkeypatch.setattr(httpx, "Client", boom)
    with pytest.raises(ValueError) as excinfo:
        JSFetcher().fetch_url("https://self-signed.example.com/app.js")
    assert "insecure" in str(excinfo.value).lower()


def test_fetch_url_wraps_generic_network_error(monkeypatch):
    def boom(*args, **kwargs):
        raise httpx.ConnectError("Connection refused")

    monkeypatch.setattr(httpx, "Client", boom)
    with pytest.raises(ValueError, match="Network error"):
        JSFetcher().fetch_url("https://down.example.com/app.js")

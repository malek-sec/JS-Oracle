"""Tests for CLI helper parsing (headers, URL lists)."""

import pytest

from main import _parse_headers, _read_url_list


def test_parse_headers_valid():
    out = _parse_headers(("Authorization: Bearer abc", "X-Env:staging"))
    assert out == {"Authorization": "Bearer abc", "X-Env": "staging"}


def test_parse_headers_empty_tuple():
    assert _parse_headers(()) == {}


def test_parse_headers_rejects_missing_colon():
    with pytest.raises(ValueError, match="Expected 'Name: Value'"):
        _parse_headers(("NoColonHere",))


def test_parse_headers_rejects_empty_name():
    with pytest.raises(ValueError, match="Empty header name"):
        _parse_headers((": value",))


def test_read_url_list_skips_blanks_and_comments(tmp_path):
    f = tmp_path / "urls.txt"
    f.write_text(
        "https://a.com/app.js\n"
        "\n"
        "# a comment\n"
        "  https://b.com/main.js  \n",
        encoding="utf-8",
    )
    assert _read_url_list(str(f)) == ["https://a.com/app.js", "https://b.com/main.js"]


def test_read_url_list_missing_file_raises(tmp_path):
    import click
    with pytest.raises(click.UsageError):
        _read_url_list(str(tmp_path / "nope.txt"))

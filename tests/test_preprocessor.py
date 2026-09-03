"""Tests for minification detection and beautify fault tolerance."""

import jsbeautifier

from core.preprocessor import JSPreprocessor


def test_is_minified_detects_long_single_line():
    p = JSPreprocessor()
    assert p.is_minified("var a=1;" * 200) is True          # one dense line
    assert p.is_minified("") is False
    normal = "\n".join(["const x = 1;", "function f() {", "  return x;", "}"])
    assert p.is_minified(normal) is False


def test_beautify_falls_back_to_raw_on_error(monkeypatch):
    p = JSPreprocessor()
    minified = "var a=1;" * 200

    def boom(*args, **kwargs):
        raise RuntimeError("beautify exploded")

    monkeypatch.setattr(jsbeautifier, "beautify", boom)
    # Must not raise — falls back to the original content.
    assert p.beautify(minified) == minified


def test_prepare_returns_single_chunk_for_small_input():
    p = JSPreprocessor()
    chunks = p.prepare("const x = 1;\n")
    assert isinstance(chunks, list) and len(chunks) == 1

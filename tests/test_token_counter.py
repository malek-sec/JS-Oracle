"""Tests for token estimation and chunking."""

from utils.token_counter import TokenCounter


def test_estimate_is_quarter_of_length():
    tc = TokenCounter()
    assert tc.estimate("a" * 400) == 100


def test_needs_chunking_threshold():
    tc = TokenCounter()
    small = "x" * 1000
    assert tc.needs_chunking(small) is False
    big = "x" * (tc.CLAUDE_SAFE_LIMIT * 4 + 8)
    assert tc.needs_chunking(big) is True


def test_calculate_chunks_covers_all_lines_with_overlap():
    tc = TokenCounter()
    # Shrink the budget so a modest input genuinely splits into several chunks.
    tc.CLAUDE_SAFE_LIMIT = 200
    lines = [f"line{i}" for i in range(1000)]
    text = "\n".join(lines)
    overlap = 5
    chunks = tc.calculate_chunks(text, overlap_lines=overlap)

    assert len(chunks) > 1  # actually split

    # No line is ever dropped between chunks.
    seen = set()
    for c in chunks:
        seen.update(c.splitlines())
    assert seen == set(lines)

    # Consecutive chunks overlap by exactly `overlap` lines.
    first, second = chunks[0].splitlines(), chunks[1].splitlines()
    assert first[-overlap:] == second[:overlap]


def test_calculate_chunks_empty_text():
    tc = TokenCounter()
    assert tc.calculate_chunks("") == []

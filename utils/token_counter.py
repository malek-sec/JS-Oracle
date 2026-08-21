"""Counts tokens in text content for LLM context management."""


class TokenCounter:
    CLAUDE_SAFE_LIMIT = 180_000

    def estimate(self, text: str) -> int:
        return len(text) // 4

    def needs_chunking(self, text: str) -> bool:
        return self.estimate(text) > self.CLAUDE_SAFE_LIMIT

    def calculate_chunks(self, text: str, overlap_lines: int = 200) -> list[str]:
        lines = text.splitlines()
        if not lines:
            return []

        # Estimate characters per line to derive a safe line budget per chunk
        avg_chars_per_line = max(len(text) / len(lines), 1)
        lines_per_chunk = int((self.CLAUDE_SAFE_LIMIT * 4) / avg_chars_per_line)
        lines_per_chunk = max(lines_per_chunk, overlap_lines + 1)

        chunks: list[str] = []
        start = 0
        while start < len(lines):
            end = start + lines_per_chunk
            chunk_lines = lines[start:end]
            chunks.append("\n".join(chunk_lines))
            if end >= len(lines):
                break
            # Next chunk begins overlap_lines before the current end
            start = end - overlap_lines

        return chunks


token_counter = TokenCounter()

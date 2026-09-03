"""Preprocesses and cleans raw JavaScript content before analysis."""

import jsbeautifier

from utils.logger import logger
from utils.token_counter import token_counter


class JSPreprocessor:

    def __init__(self):
        self.opts = jsbeautifier.default_options()
        self.opts.indent_size = 2
        self.opts.preserve_newlines = True
        self.opts.max_preserve_newlines = 2

    def is_minified(self, content: str) -> bool:
        if not content:
            return False
        lines = content.splitlines()
        total_lines = len(lines)
        total_chars = len(content)
        if total_lines == 0:
            return False
        if total_lines < 5 and total_chars > 500:
            return True
        return (total_chars / total_lines) > 200

    def beautify(self, content: str) -> str:
        if self.is_minified(content):
            logger.debug("Minified JS detected — running beautifier.")
            try:
                return jsbeautifier.beautify(content, self.opts)
            except Exception as e:
                # Beautify is a readability nicety, not a hard requirement —
                # never let malformed input abort analysis over it.
                logger.warning(f"Beautifier failed ({e}); analyzing raw content.")
                return content
        logger.debug("JS does not appear minified — skipping beautifier.")
        return content

    def prepare(self, content: str) -> list[str]:
        content = self.beautify(content)
        if token_counter.needs_chunking(content):
            chunks = token_counter.calculate_chunks(content)
            logger.debug(f"Content split into {len(chunks)} chunk(s) for context limit.")
            return chunks
        logger.debug("Content fits in a single chunk.")
        return [content]


preprocessor = JSPreprocessor()

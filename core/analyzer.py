"""Analyzes JavaScript content and extracts insights."""

import copy
import json
import os
import random
import time
import anthropic
from anthropic import APIConnectionError, APIError, APIStatusError, RateLimitError
from google import genai
from google.genai import types as genai_types
from google.genai import errors as genai_errors

from core.cache import analysis_cache
from utils.logger import logger

# AI_PROVIDER selects which backend to call. Defaults to "gemini" (free tier).
# Set AI_PROVIDER=anthropic to switch back to the paid Claude models.
_DEFAULT_MODELS = {"gemini": "gemini-2.5-flash", "anthropic": "claude-sonnet-4-6"}

_PROVIDER = os.environ.get("AI_PROVIDER", "gemini").strip().lower()
if _PROVIDER not in _DEFAULT_MODELS:
    raise ValueError(
        f"Invalid AI_PROVIDER={_PROVIDER!r}. Valid options: {', '.join(sorted(_DEFAULT_MODELS))}."
    )

# Bump this whenever _SYSTEM_PROMPT or _OUTPUT_SCHEMA changes, so cached
# results from an older prompt version are never served under a new one.
_PROMPT_VERSION = "v1"

# Stable portion of the prompt — cached on first call.
# The variable sections (target domain, JS code) are injected per-request via the user message.
_SYSTEM_PROMPT = """\
You are an elite offensive security analyst specialized in JavaScript \
reverse engineering for authorized bug bounty engagements. Your sole \
task is to extract actionable intelligence from JS code.

## RULES (NON-NEGOTIABLE)
1. Output ONLY valid JSON matching the exact schema below. No markdown, \
no code fences, no commentary, no apologies.
2. If a field has no findings, return an empty array []. Never omit keys.
3. Do NOT hallucinate. If you are not 80%+ confident, exclude the finding. \
False negatives are better than false positives.
4. If a target domain is provided, exclude endpoints whose host is clearly \
third-party (analytics, ads, CDNs, social widgets, fonts).
5. For every finding, quote the EXACT source snippet (max 120 chars). \
No paraphrasing, no summarizing.

## OUTPUT SCHEMA (STRICT — return this structure ONLY)
{
  "analysis_summary": {
    "total_findings": 0,
    "highest_severity": "critical|high|medium|low|none"
  },
  "endpoints": [
    {
      "path": "string",
      "method": "GET|POST|PUT|DELETE|PATCH|UNKNOWN",
      "parameters": [],
      "body_structure": null,
      "evidence": "string, max 120 chars",
      "confidence": "high|medium|low"
    }
  ],
  "secrets": [
    {
      "type": "api_key|aws_key|jwt|internal_ip|token|other",
      "value_preview": "first 8 chars + ***",
      "evidence": "string, max 120 chars"
    }
  ],
  "auth_logic": [
    {
      "mechanism": "string",
      "storage_location": "localStorage|sessionStorage|cookie|memory|unknown",
      "evidence": "string, max 120 chars"
    }
  ],
  "suspicious_logic": [
    {
      "description": "string",
      "severity": "critical|high|medium|low|info",
      "evidence": "string, max 120 chars"
    }
  ]
}\
"""

_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "analysis_summary": {
            "type": "object",
            "properties": {
                "total_findings": {"type": "integer"},
                "highest_severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "none"],
                },
            },
            "required": ["total_findings", "highest_severity"],
            "additionalProperties": False,
        },
        "endpoints": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "UNKNOWN"],
                    },
                    "parameters": {"type": "array", "items": {"type": "string"}},
                    "body_structure": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "evidence": {"type": "string"},
                    "confidence": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                    },
                },
                "required": ["path", "method", "parameters", "body_structure", "evidence", "confidence"],
                "additionalProperties": False,
            },
        },
        "secrets": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {
                        "type": "string",
                        "enum": ["api_key", "aws_key", "jwt", "internal_ip", "token", "other"],
                    },
                    "value_preview": {"type": "string"},
                    "evidence": {"type": "string"},
                },
                "required": ["type", "value_preview", "evidence"],
                "additionalProperties": False,
            },
        },
        "auth_logic": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "mechanism": {"type": "string"},
                    "storage_location": {
                        "type": "string",
                        "enum": ["localStorage", "sessionStorage", "cookie", "memory", "unknown"],
                    },
                    "evidence": {"type": "string"},
                },
                "required": ["mechanism", "storage_location", "evidence"],
                "additionalProperties": False,
            },
        },
        "suspicious_logic": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "description": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                    },
                    "evidence": {"type": "string"},
                },
                "required": ["description", "severity", "evidence"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["analysis_summary", "endpoints", "secrets", "auth_logic", "suspicious_logic"],
    "additionalProperties": False,
}

_MAX_RETRIES = 5
_BASE_DELAY = 2.0
_MAX_DELAY = 60.0

_MOCK_RESPONSE = {
    "analysis_summary": {
        "total_findings": 3,
        "highest_severity": "high",
    },
    "endpoints": [
        {
            "path": "/api/mock/users",
            "method": "GET",
            "parameters": ["id", "role"],
            "body_structure": None,
            "evidence": "mockEndpoint = '/api/mock/users'",
            "confidence": "high",
        },
        {
            "path": "/api/mock/admin",
            "method": "POST",
            "parameters": [],
            "body_structure": '{"username": "string", "password": "string"}',
            "evidence": "fetch('/api/mock/admin', {method: 'POST'})",
            "confidence": "medium",
        },
    ],
    "secrets": [
        {
            "type": "api_key",
            "value_preview": "MOCK_KEY***",
            "evidence": "apiKey = 'MOCK_KEY_1234567890'",
        }
    ],
    "auth_logic": [
        {
            "mechanism": "JWT stored after login",
            "storage_location": "localStorage",
            "evidence": "localStorage.setItem('token', response.jwt)",
        }
    ],
    "suspicious_logic": [
        {
            "description": "Mock: Admin bypass flag found in source",
            "severity": "high",
            "evidence": "if (debugMode) { bypassAuth = true; }",
        }
    ],
}


class JSAnalyzer:

    def __init__(self, model: str | None = None):  # noqa: keep in sync with main.py default
        self.provider = _PROVIDER
        self.model = model or _DEFAULT_MODELS.get(self.provider, _DEFAULT_MODELS["gemini"])
        if self.provider == "anthropic":
            self.client = anthropic.Anthropic()
        else:
            self.client = genai.Client()

    def _call_with_retry(self, **kwargs):
        """Wrap the provider's create call with exponential backoff and jitter.

        Retries on rate limits, connection errors, and 5xx server errors.
        Non-retryable errors (4xx except 429, auth failures) are re-raised immediately.
        """
        if self.provider == "anthropic":
            return self._call_anthropic_with_retry(**kwargs)
        return self._call_gemini_with_retry(**kwargs)

    def _call_anthropic_with_retry(self, **kwargs):
        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES + 1):
            try:
                return self.client.messages.create(**kwargs)
            except RateLimitError as e:
                last_exc = e
            except APIConnectionError as e:
                last_exc = e
            except APIStatusError as e:
                if e.status_code >= 500:
                    last_exc = e
                else:
                    # 4xx errors other than 429 are caller bugs — don't retry.
                    raise
            except APIError as e:
                # Catch-all for other Anthropic API errors — raise immediately.
                raise

            if attempt < _MAX_RETRIES:
                delay = min(_BASE_DELAY * (2 ** attempt) + random.uniform(0, 1), _MAX_DELAY)
                logger.warning(
                    f"API call failed (attempt {attempt + 1}/{_MAX_RETRIES + 1}): "
                    f"{last_exc!r}. Retrying in {delay:.1f}s..."
                )
                time.sleep(delay)

        raise last_exc

    def _call_gemini_with_retry(self, *, model, contents, config):
        last_exc: Exception | None = None

        for attempt in range(_MAX_RETRIES + 1):
            try:
                return self.client.models.generate_content(model=model, contents=contents, config=config)
            except genai_errors.ServerError as e:
                last_exc = e
            except genai_errors.ClientError as e:
                if e.code == 429:
                    last_exc = e
                else:
                    # 4xx errors other than 429 are caller bugs — don't retry.
                    raise

            if attempt < _MAX_RETRIES:
                delay = min(_BASE_DELAY * (2 ** attempt) + random.uniform(0, 1), _MAX_DELAY)
                logger.warning(
                    f"API call failed (attempt {attempt + 1}/{_MAX_RETRIES + 1}): "
                    f"{last_exc!r}. Retrying in {delay:.1f}s..."
                )
                time.sleep(delay)

        raise last_exc

    def analyze(self, content: str, target_domain: str = "", use_cache: bool = True, dry_run: bool = False) -> dict:
        """Send JS content to the configured AI provider and return parsed findings as a dict.

        Args:
            content: Raw (or pre-beautified) JavaScript source.
            target_domain: Optional target domain for third-party endpoint filtering.
            use_cache: When False, skip both cache read and write.
            dry_run: When True, skip the API call and return a mock response.
        """
        if dry_run:
            logger.info("DRY RUN — skipping API call, returning mock response.")
            return copy.deepcopy(_MOCK_RESPONSE)

        if use_cache:
            cached = analysis_cache.get(content, self.provider, self.model, _PROMPT_VERSION)
            if cached:
                return cached

        domain_note = target_domain if target_domain else "none specified"
        user_message = (
            f"## TARGET DOMAIN\n{domain_note}\n\n"
            f"## JS CODE\n{content}"
        )

        logger.debug(f"Sending {len(content):,} chars to {self.model} ({self.provider}) for analysis.")

        if self.provider == "anthropic":
            response = self._call_with_retry(
                model=self.model,
                max_tokens=16384,
                system=[
                    {
                        "type": "text",
                        "text": _SYSTEM_PROMPT,
                        # Cache the stable system prompt so repeated calls only pay for
                        # the JS code tokens, not the full instruction block.
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                output_config={
                    "format": {
                        "type": "json_schema",
                        "schema": _OUTPUT_SCHEMA,
                    }
                },
                messages=[{"role": "user", "content": user_message}],
            )

            if response.stop_reason == "refusal":
                raise ValueError("Claude refused the request. Content may violate usage policies.")

            if response.stop_reason == "max_tokens":
                raise ValueError(
                    "Response was truncated (hit max_tokens limit). "
                    "The JS file may be too complex for a single analysis — consider chunking."
                )

            if response.stop_reason != "end_turn":
                logger.warning(f"Unexpected stop_reason: {response.stop_reason}")

            text_blocks = [b.text for b in response.content if b.type == "text"]
            if not text_blocks:
                raise ValueError("API response contained no text blocks.")
            text = text_blocks[0]
        else:
            response = self._call_with_retry(
                model=self.model,
                contents=user_message,
                config=genai_types.GenerateContentConfig(
                    system_instruction=_SYSTEM_PROMPT,
                    max_output_tokens=16384,
                    response_mime_type="application/json",
                    response_json_schema=_OUTPUT_SCHEMA,
                ),
            )

            finish_reason = response.candidates[0].finish_reason if response.candidates else None
            if finish_reason == genai_types.FinishReason.SAFETY:
                raise ValueError("Gemini refused the request. Content may violate usage policies.")

            if finish_reason == genai_types.FinishReason.MAX_TOKENS:
                raise ValueError(
                    "Response was truncated (hit max_tokens limit). "
                    "The JS file may be too complex for a single analysis — consider chunking."
                )

            if finish_reason != genai_types.FinishReason.STOP:
                logger.warning(f"Unexpected finish_reason: {finish_reason}")

            text = response.text
            if not text:
                raise ValueError("API response contained no text.")

        try:
            result: dict = json.loads(text)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse API response as JSON: {e}")
            logger.debug(f"Raw response text: {text[:500]}...")
            raise ValueError("API returned malformed JSON despite structured output constraint.") from e

        total = result.get("analysis_summary", {}).get("total_findings", "?")
        severity = result.get("analysis_summary", {}).get("highest_severity", "?")
        logger.info(f"Analysis complete — {total} finding(s), highest severity: {severity}")

        if self.provider == "anthropic":
            cache_read = getattr(response.usage, "cache_read_input_tokens", 0)
            if cache_read:
                logger.debug(f"Prompt cache hit: {cache_read:,} tokens served from cache.")

        if use_cache:
            analysis_cache.set(content, self.provider, self.model, _PROMPT_VERSION, result)

        return result


analyzer = JSAnalyzer()

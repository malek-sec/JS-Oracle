"""Offline, deterministic pre-scans that need no API call.

These complement the LLM analysis with cheap, high-confidence signals:
  * source-map references (frequently leak a bundle's original source),
  * well-known secret formats (AWS, Google, GitHub, GitLab, npm, Slack, Twilio,
    SendGrid, Mailgun, Stripe, Square, Anthropic, OpenAI, JWTs, private keys),
  * private (RFC 1918) IP addresses,
  * and — opt-in — a LinkFinder-style endpoint/URL sweep.

Findings are emitted in the standard result shape so the merger can dedupe them
against (and enrich) the model's findings.
"""

import re

# ── source maps ──────────────────────────────────────────────────────────────
# Matches  //# sourceMappingURL=app.js.map  and the older  //@ ...  form.
_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", re.IGNORECASE)

# ── secrets (curated, high-confidence formats only, to keep false positives low) ──
# Each entry maps to a `type` from the output schema's secret enum.
_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    # ── cloud / infra ────────────────────────────────────────────────────────
    ("aws_key", re.compile(r"A(?:KIA|SIA)[0-9A-Z]{16}")),                        # AWS access key id
    ("api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),                          # Google API key
    ("api_key", re.compile(r"GOCSPX-[0-9A-Za-z_\-]{28}")),                       # Google OAuth client secret
    ("api_key", re.compile(r"ya29\.[0-9A-Za-z_\-]{20,}")),                       # Google OAuth access token
    # ── source hosting ───────────────────────────────────────────────────────
    ("token",   re.compile(r"gh[pousr]_[0-9A-Za-z]{36,255}")),                   # GitHub token (classic)
    ("token",   re.compile(r"github_pat_[0-9A-Za-z_]{82}")),                     # GitHub fine-grained PAT
    ("token",   re.compile(r"glpat-[0-9A-Za-z_\-]{20}")),                        # GitLab PAT
    ("token",   re.compile(r"npm_[0-9A-Za-z]{36}")),                             # npm access token
    # ── messaging / comms ────────────────────────────────────────────────────
    ("token",   re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),                  # Slack token
    ("token",   re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z]+")),  # Slack webhook
    ("token",   re.compile(r"SK[0-9a-f]{32}")),                                  # Twilio API key
    ("api_key", re.compile(r"SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}")),      # SendGrid API key
    ("api_key", re.compile(r"key-[0-9a-f]{32}")),                                # Mailgun API key
    # ── payments ─────────────────────────────────────────────────────────────
    ("token",   re.compile(r"[sr]k_live_[0-9a-zA-Z]{24,}")),                     # Stripe secret / restricted key
    ("token",   re.compile(r"sq0(?:atp|csp)-[0-9A-Za-z_\-]{22}")),               # Square access/OAuth token
    # ── AI providers ─────────────────────────────────────────────────────────
    ("api_key", re.compile(r"sk-ant-[0-9A-Za-z_\-]{20,}")),                      # Anthropic API key
    ("api_key", re.compile(r"sk-(?:proj-)?[0-9A-Za-z]{20,}")),                   # OpenAI API key
    # ── generic high-confidence ──────────────────────────────────────────────
    ("jwt",     re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("other",   re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
]

# RFC 1918 private ranges: 10/8, 192.168/16, 172.16–31/12.
_INTERNAL_IP_RE = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}"
    r"|192\.168(?:\.\d{1,3}){2}"
    r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
)

# ── endpoints (opt-in — noisier) ─────────────────────────────────────────────
_FULL_URL_RE = re.compile(r"https?://[^\s\"'`<>()\[\]{}]{4,}")
# Conservative: only quoted relative paths that begin with a common API-ish segment.
_REL_PATH_RE = re.compile(
    r"""['"](/(?:api|v\d+|graphql|gql|rest|auth|oauth|admin|internal|users?|accounts?|"""
    r"""session|token|login|logout|signup|register|payments?|webhooks?)"""
    r"""[A-Za-z0-9_\-/.{}:]*)['"]"""
)

_EMPTY = {
    "analysis_summary": {"total_findings": 0, "highest_severity": "none"},
    "endpoints": [],
    "secrets": [],
    "auth_logic": [],
    "suspicious_logic": [],
}

# Well-known third-party JS libraries — analyzing these with an LLM is wasted
# spend (no custom logic to find). Matched against the file name only.
_KNOWN_LIB_RE = re.compile(
    r"(?:^|[/_-])(?:"
    r"jquery|jquery[.-]migrate|jquery[.-]ui|jquery[.-]validate|jquery[.-]blockui|"
    r"bootstrap|popper|angular|react|react-dom|vue|lodash|underscore|moment|"
    r"gsap|greensock|tweenmax|tweenlite|timelinemax|scrolltoplugin|scrollmagic|"
    r"owl[.-]?carousel|slick|select2|selectwoo|swiper|aos|wow|parallax|"
    r"fontawesome|font-awesome|modernizr|handlebars|mustache|d3|chart|"
    r"easing|wp-polyfill|regenerator-runtime|zxcvbn|js[.-]cookie|"
    r"hooks[.-]min|i18n[.-]min|dom-ready|hoverintent|imagesloaded|masonry"
    r")(?:[.-]|$)",
    re.IGNORECASE,
)


def is_known_library(name: str) -> bool:
    """Heuristic: does this URL/filename look like a third-party JS library?

    Matches the file name (last path segment, sans query) so a path directory
    can't trigger a false positive. Intended for the opt-in ``--skip-libs``.
    """
    filename = (name or "").rsplit("/", 1)[-1].split("?", 1)[0]
    return bool(_KNOWN_LIB_RE.search(filename))


def _mask(value: str) -> str:
    """Mask a secret to a short, non-sensitive preview (mirrors the LLM convention)."""
    v = value.strip()
    return (v[:8] + "***") if len(v) > 8 else (v[:2] + "***")


def find_source_maps(content: str) -> list[str]:
    """Return the unique source-map URLs referenced in ``content``."""
    seen: list[str] = []
    for match in _SOURCEMAP_RE.finditer(content or ""):
        url = match.group(1).strip().strip("\"'")
        if url and url not in seen:
            seen.append(url)
    return seen


def find_secrets(content: str) -> list[dict]:
    """Return high-confidence secret findings (deduped) in schema shape."""
    out: list[dict] = []
    seen: set[tuple] = set()

    def _add(stype: str, value: str) -> None:
        key = (stype, value)
        if key in seen:
            return
        seen.add(key)
        out.append({"type": stype, "value_preview": _mask(value), "evidence": value[:120]})

    text = content or ""
    for stype, rx in _SECRET_PATTERNS:
        for m in rx.finditer(text):
            _add(stype, m.group(0))
    for m in _INTERNAL_IP_RE.finditer(text):
        _add("internal_ip", m.group(0))
    return out


def find_endpoints(content: str) -> list[dict]:
    """Return endpoint findings from a LinkFinder-style regex sweep (schema shape)."""
    out: list[dict] = []
    seen: set[str] = set()

    def _add(path: str, evidence: str) -> None:
        if path in seen:
            return
        seen.add(path)
        out.append({
            "path": path,
            "method": "UNKNOWN",
            "parameters": [],
            "body_structure": None,
            "evidence": evidence[:120],
            "confidence": "low",  # regex-derived — the LLM's own findings outrank these
        })

    text = content or ""
    for m in _FULL_URL_RE.finditer(text):
        _add(m.group(0).rstrip("\\\",;)"), m.group(0))
    for m in _REL_PATH_RE.finditer(text):
        _add(m.group(1), m.group(0))
    return out


def offline_findings(content: str, include_endpoints: bool = False) -> dict:
    """Run the offline scans and return findings in the standard result shape.

    Source maps and secrets are always scanned (high value, low noise). The
    endpoint sweep is opt-in via ``include_endpoints`` because it is noisier.
    """
    suspicious = [
        {
            "description": f"Source map referenced ({url}) — may expose original source",
            "severity": "info",
            "evidence": (f"//# sourceMappingURL={url}")[:120],
        }
        for url in find_source_maps(content)
    ]
    return {
        **_EMPTY,
        "endpoints": find_endpoints(content) if include_endpoints else [],
        "secrets": find_secrets(content),
        "suspicious_logic": suspicious,
    }

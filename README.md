# JS Oracle

**AI-powered JavaScript analysis for bug bounty hunters.** Point it at a JS file,
URL, or directory and it extracts **endpoints, secrets, authentication logic, and
suspicious patterns** into clean terminal, Markdown, and JSON reports.

By default it uses **Claude (Anthropic)** with a strict JSON schema so the output
is always machine-parseable. Google **Gemini** is supported as an optional
free-tier alternative.

---

## Features

- 🔎 Extracts API **endpoints** (path, method, parameters, body shape) with confidence scores
- 🔑 Flags likely **secrets** (API keys, JWTs, tokens, internal IPs) — value-masked
- 🔐 Maps **auth logic** (token storage, mechanisms)
- ⚠️ Surfaces **suspicious logic** with severity
- 🗺️ Offline, zero-cost **deterministic scans** (run even without/before the API): source-map
  leaks, **known secret formats** (AWS/Google/GitHub/Slack/Stripe/JWT/private keys), private IPs,
  and an opt-in LinkFinder-style **endpoint sweep** (`--regex-endpoints`)
- 📃 Batch-analyze a **list of remote JS URLs** (feed it `katana`/`gau` output via `--url-list -`)
- 🕵️ **Proxy / custom headers / TLS-skip** for fetching through Burp or behind auth
- ⚡ **Concurrency** (`-c N`) to analyze many sources in parallel
- 🧹 Auto-beautifies minified bundles and **chunks** oversized files to fit the context window
- 🌐 Filters out **third-party** endpoints when you give it a target domain
- 💾 Local **cache** keyed by content + provider + model + prompt version (no repeat spend)
- 🧾 Structured **Markdown + JSON + HTML** reports (`--html`), a rich terminal summary, and a **batch summary**

---

## Install

Requires **Python 3.10+**.

```bash
# Clone, then from the project root:
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux/macOS:  source .venv/bin/activate

# Option A — quick start (default Claude / Opus provider):
pip install -r requirements.txt

# Option B — packaged install, adds a `js-oracle` command:
pip install .            # Claude provider only (same deps as Option A)
pip install .[dev]       # + test/lint tooling

# Gemini is OPTIONAL — only if you switch to AI_PROVIDER=gemini:
pip install .[gemini]    # (or: pip install google-genai)
```

## Configure

Copy the template and fill in a key:

```bash
cp .env.example .env
```

```ini
AI_PROVIDER=anthropic                       # "anthropic" (default) or "gemini"
ANTHROPIC_API_KEY="sk-ant-..."              # required for the default provider
ANTHROPIC_EFFORT=medium                     # low | medium | high | xhigh | max
# GEMINI_API_KEY="..."                      # only if AI_PROVIDER=gemini
```

- **Default model:** `claude-opus-4-8` at `effort=medium`. Override the model per run with `--model`.
- **Gemini:** set `AI_PROVIDER=gemini` and `GEMINI_API_KEY`, and install the extra (`pip install .[gemini]`). Default model there is `gemini-2.5-flash`.

## Usage

```bash
# A single remote JS file
js-oracle analyze --url https://target.com/static/app.js --domain target.com

# Several URLs at once (repeat -u)
js-oracle analyze -u https://t.com/a.js -u https://t.com/b.js --domain t.com

# A list of JS URLs from your recon pipeline — parallel, with HTML reports
katana -u https://target.com -silent | grep '\.js$' \
  | js-oracle analyze --url-list - --domain target.com -c 5 --html

# Through Burp, skipping TLS checks, with an auth header
js-oracle analyze -u https://target.com/app.js --proxy http://127.0.0.1:8080 --insecure -H "Authorization: Bearer TOKEN"

# A local file, or a whole directory (recursive *.js)
js-oracle analyze --file ./bundle.min.js
js-oracle analyze --dir ./downloaded_js --domain target.com

# Test the pipeline end-to-end without spending API tokens
js-oracle analyze -f app.js --dry-run

# Version / clear the local cache
js-oracle --version
js-oracle clear-cache
```

> Not installed as a command? Run it as a module instead: `python main.py analyze ...`

### Options

| Flag | Description |
|------|-------------|
| `--url, -u` | JS file URL (repeatable) |
| `--url-list` | File of JS URLs, one per line (`-` reads stdin) |
| `--file, -f` | Local JS file path |
| `--dir, -d` | Directory of JS files (recursive) |
| `--domain` | Target domain — drops third-party endpoints |
| `--output, -o` | Report output dir (default `./reports`) |
| `--html` | Also write HTML per source + a batch `index.html` |
| `--regex-endpoints` | Add an offline LinkFinder-style endpoint sweep (noisier) |
| `--concurrency, -c` | Analyze N sources in parallel (default 1) |
| `--proxy` | Route URL fetches through a proxy (e.g. Burp) |
| `--insecure` | Skip TLS certificate verification when fetching |
| `--header, -H` | Extra request header `Name: Value` (repeatable) |
| `--model, -m` | Override the model for this run |
| `--chunk-delay` | Seconds between chunk API calls (default 5) |
| `--no-cache` | Disable read + write of the cache |
| `--dry-run` | Run fetch/chunk/merge/report with a mock response — no API call |
| `--verbose, -v` | Debug logging + full tracebacks |

Top-level: `js-oracle --version`, `js-oracle clear-cache`.

## Output

For each source you get:

- a **terminal** summary (rich tables),
- `reports/<slug>_<hash>.md` — human-readable Markdown,
- `reports/<slug>_<hash>.json` — the raw structured findings.

The `<hash>` suffix guarantees two different sources never overwrite each other's report.

## How it works

```
fetch → beautify (if minified) → chunk (if oversized) → analyze (LLM, strict JSON)
      → + offline scan (secrets, source maps, IPs, [endpoints]) → merge + dedupe
      → filter third-party → report (terminal / MD / JSON / HTML)
```

## Security notes

- Analyzed JavaScript is treated as **untrusted data** and wrapped in explicit
  delimiters; the system prompt instructs the model to ignore any instructions
  embedded in the code (prompt-injection hardening).
- Secret **values are masked** in reports (preview only).
- `.env`, `.cache/`, and `reports/` are git-ignored. Never commit real keys.
- Only analyze assets you are **authorized** to test.

## Development

```bash
pip install .[dev]
pytest
```

## License

MIT — see [LICENSE](LICENSE).

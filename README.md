# JS-Oracle

JavaScript analysis for bug bounty hunters. Point it at a file, a URL, or a
directory and it extracts endpoints, secrets, authentication logic, and
suspicious patterns into terminal, Markdown, JSON, and HTML reports.

Analysis runs through Claude by default, constrained to a strict JSON schema so
the output is always machine-parseable. Gemini is supported as an optional
alternative. A deterministic offline mode runs the whole pipeline with no model,
no API key, and no cost.

JS-Oracle stands alone, and also serves as Module 4 of
[scan-engine](https://github.com/malek-sec/scan-engine), the pipeline behind
[BountyHub](https://github.com/malek-sec/BountyHub).

> Only analyse assets you are authorised to test.

---

## Why it exists

Modern applications put their real attack surface in JavaScript. The API routes,
the parameter names, the feature flags, the occasional key someone shipped by
mistake — it is all in the bundle, buried under a megabyte of minified vendor
code. Reading it by hand does not scale. Feeding all of it to a model is
expensive and mostly pays for analysing jQuery.

JS-Oracle splits the difference. A deterministic pass catches what regex catches
reliably — known key formats, source maps, private IPs — for free. The model gets
the remaining custom code, beautified and chunked to fit, and returns structured
findings. Both sets are merged, deduplicated, and filtered against your target
domain so third-party endpoints do not clutter the report.

## Features

- Extracts API endpoints with path, method, parameters, body shape, and a
  confidence score
- Flags likely secrets — API keys, JWTs, tokens, internal IPs — with values
  masked in the output
- Maps authentication logic, including token storage and mechanism
- Surfaces suspicious logic with severity
- Offline deterministic scan: source-map leaks, known secret formats
  (AWS, Google, GitHub, Slack, Stripe, JWT, private keys), private IPs, and an
  opt-in LinkFinder-style endpoint sweep
- Batch-analyses a list of remote JS URLs, so `katana` or `gau` output pipes
  straight in
- Proxy, custom headers, and TLS-skip for fetching through Burp or behind auth
- Parallel analysis across sources
- Auto-beautifies minified bundles and chunks oversized files to fit the context
  window
- Filters third-party endpoints when given a target domain
- Local cache keyed by content, provider, model, and prompt version, so identical
  content is never paid for twice
- Markdown, JSON, and HTML reports plus a rich terminal summary and batch index

## Install

Requires Python 3.10 or newer.

```bash
git clone https://github.com/malek-sec/JS-Oracle.git
cd JS-Oracle

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# Option A - quick start
pip install -r requirements.txt

# Option B - packaged install, adds a `js-oracle` command
pip install .
pip install .[dev]                 # with test and lint tooling

# Gemini is optional, only for AI_PROVIDER=gemini
pip install .[gemini]
```

## Configure

```bash
cp .env.example .env
```

```ini
AI_PROVIDER=anthropic              # "anthropic" (default) or "gemini"
ANTHROPIC_API_KEY="sk-ant-..."     # required for the default provider
ANTHROPIC_EFFORT=medium            # low | medium | high | xhigh | max
# ANTHROPIC_WORKSPACE_ID="wrkspc_..."   # only for identity-linked keys
# GEMINI_API_KEY="..."                  # only when AI_PROVIDER=gemini
```

The default model is `claude-opus-4-8` at `effort=medium`, overridable per run
with `--model`. Under `AI_PROVIDER=gemini` the default is `gemini-2.5-flash`.

`ANTHROPIC_WORKSPACE_ID` is only needed if the API replies that
`anthropic-workspace-id is required`; find it under Console, Settings,
Workspaces.

## Usage

```bash
# A single remote JS file
js-oracle analyze --url https://target.com/static/app.js --domain target.com

# Several URLs at once
js-oracle analyze -u https://t.com/a.js -u https://t.com/b.js --domain t.com

# A list from your recon pipeline, in parallel, with HTML reports
katana -u https://target.com -silent | grep '\.js$' \
  | js-oracle analyze --url-list - --domain target.com -c 5 --html

# Through Burp, skipping TLS checks, with an auth header
js-oracle analyze -u https://target.com/app.js \
  --proxy http://127.0.0.1:8080 --insecure -H "Authorization: Bearer TOKEN"

# A local file, or a directory tree
js-oracle analyze --file ./bundle.min.js
js-oracle analyze --dir ./downloaded_js --domain target.com

# Exercise the full pipeline without spending tokens
js-oracle analyze -f app.js --dry-run

js-oracle --version
js-oracle clear-cache
```

Not installed as a command? Run it as a module: `python3 main.py analyze ...`

### Options

| Flag | Description |
|---|---|
| `--url`, `-u` | JS file URL (repeatable) |
| `--url-list` | File of JS URLs, one per line (`-` reads stdin) |
| `--file`, `-f` | Local JS file path |
| `--dir`, `-d` | Directory of JS files (recursive) |
| `--domain` | Target domain — drops third-party endpoints |
| `--output`, `-o` | Report output directory (default `./reports`) |
| `--html` | Also write HTML per source plus a batch `index.html` |
| `--offline` | Deterministic scan only — no model call, no key, no cost |
| `--skip-libs` | Skip known JS libraries (jquery, bootstrap, gsap, and so on) |
| `--regex-endpoints` | Add an offline LinkFinder-style endpoint sweep (noisier) |
| `--concurrency`, `-c` | Analyse N sources in parallel (default 1) |
| `--proxy` | Route URL fetches through a proxy, such as Burp |
| `--insecure` | Skip TLS certificate verification when fetching |
| `--header`, `-H` | Extra request header `Name: Value` (repeatable) |
| `--model`, `-m` | Override the model for this run |
| `--chunk-delay` | Seconds between chunk API calls (default 5) |
| `--no-cache` | Disable cache reads and writes |
| `--dry-run` | Full pipeline with a mock response — no API call |
| `--verbose`, `-v` | Debug logging and full tracebacks |

## Controlling cost

Minified bundles are token-heavy and Opus is a premium model, so a large batch
adds up fast. A three-pass workflow keeps the spend on the files that deserve it:

```bash
# 1. Free triage over the whole list — deterministic, no model
js-oracle analyze --url-list all_js.txt --offline --skip-libs --domain target.com

# 2. Bulk AI pass on the Gemini free tier, skipping vendor libraries
js-oracle analyze --url-list all_js.txt --skip-libs -c 5 --domain target.com

# 3. Deep Opus pass on the few interesting custom files
js-oracle analyze -u https://target.com/assets/app.js --domain target.com
```

The levers, roughly in order of impact: `--offline` costs nothing at all,
`--skip-libs` drops vendor code, `AI_PROVIDER=gemini` uses the free tier,
`--model claude-haiku-4-5` is around five times cheaper than Opus,
`ANTHROPIC_EFFORT=low` reduces deliberation, and the cache means re-running
identical content never charges twice.

## Output

For each source:

- a terminal summary in rich tables
- `reports/<slug>_<hash>.md` — human-readable Markdown
- `reports/<slug>_<hash>.json` — raw structured findings
- `reports/<slug>_<hash>.html` — styled report, with `--html`

The hash suffix guarantees two sources never overwrite each other's report.

## How it works

```
fetch -> beautify (if minified) -> chunk (if oversized) -> analyse (LLM, strict JSON)
      -> merge with offline scan (secrets, source maps, IPs, endpoints)
      -> deduplicate -> filter third-party -> report (terminal / MD / JSON / HTML)
```

Severity in the merged headline is calibrated by secret kind, so a source-map
reference does not get reported at the same level as a live AWS key.

## Security notes

- Analysed JavaScript is treated as untrusted data and wrapped in explicit
  delimiters. The system prompt instructs the model to ignore instructions
  embedded in the code, which is what stops a hostile bundle from steering its
  own analysis.
- Secret values are masked in reports. Only a preview is shown, never the full
  value.
- `.env`, `.cache/`, and `reports/` are git-ignored. Never commit real keys.
- Exit codes are honest: a failed run does not exit 0, so pipeline steps
  downstream can trust them.

## Development

```bash
pip install .[dev]
pytest
ruff check .
```

CI runs the test suite and lint across Python 3.10, 3.11, and 3.12.

## License

MIT — see [LICENSE](LICENSE).

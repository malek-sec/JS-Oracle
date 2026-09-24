# JS-Oracle

An all-in-one JavaScript reconnaissance tool for bug bounty hunters and web
application security testers. Point it at a domain and it crawls the target,
discovers and downloads every JavaScript file, then analyzes them for hidden
endpoints, API keys, secrets, and parameters — no need to run a separate
crawler or fetcher first.

Analysis has two layers:

- **Offline scan** (default, free, no API key) — deterministic regex passes for
  secrets (AWS/Google/GitHub/Slack/Stripe keys, JWTs, private keys), internal
  IPs, source-map leaks, and endpoints.
- **AI scan** (optional) — sends each file to Claude (or Gemini) to extract
  endpoints, auth logic, and suspicious patterns that regex misses. Enabled
  automatically when an API key is configured.

## Features

- **Standalone discovery** — give it a domain (`-d`) or a URL list (`-l`) and it
  finds the JavaScript itself. No `getJS`, `katana`, or `hakrawler` required.
- **Concurrent** — crawling, downloading, and analysis all run in parallel.
- **Robust** — dead links, timeouts, and TLS errors are logged and skipped, never
  fatal.
- **Wayback support** — optionally pull historic `.js` URLs from the Wayback
  Machine (`--wayback`).
- **Scope-aware** — stays on the target domain and its subdomains; filters
  third-party endpoints out of results.
- **Proxy-friendly** — route everything through Burp with `--proxy`.
- **Structured output** — clean terminal tables plus per-source JSON/Markdown
  reports, an optional HTML report, and plain-text `discovered_js.txt` /
  `parameters.txt` for piping into other tools.

## Requirements

- Python 3.10 or newer

## Installation

```bash
git clone https://github.com/malek-sec/js-oracle.git
cd js-oracle
pip install -r requirements.txt
```

Or install it as a command (adds the `js-oracle` executable to your PATH):

```bash
pip install .
```

### Optional: enable the AI scan

The offline scan needs no setup. To enable the AI-powered analysis, provide an
API key. Copy the example env file and fill it in:

```bash
cp .env.example .env
# then edit .env and set ANTHROPIC_API_KEY=sk-ant-...
```

To use Google Gemini's free tier instead of Claude:

```bash
pip install '.[gemini]'
# in .env:  AI_PROVIDER=gemini  and  GEMINI_API_KEY=...
```

If no key is found, JS-Oracle automatically falls back to the free offline scan.

## Usage

The main command is `hunt` — it does discovery and analysis in one step.

```bash
# Crawl a domain, discover its JS, and analyze it
python main.py hunt -d example.com

# Offline only (free, no API key needed)
python main.py hunt -d example.com --offline

# Deeper crawl, include historic JS from the Wayback Machine, write an HTML report
python main.py hunt -d example.com --depth 3 --wayback --html

# Start from your own list of pages or .js URLs
python main.py hunt -l urls.txt

# Route through Burp and send authenticated requests
python main.py hunt -d example.com --proxy http://127.0.0.1:8080 -H "Cookie: session=..."
```

If you installed with `pip install .`, replace `python main.py` with `js-oracle`:

```bash
js-oracle hunt -d example.com --offline
```

### Analyzing JS you already have

If you already have JS files or URLs, the `analyze` command skips discovery:

```bash
python main.py analyze -u https://example.com/app.js      # a single URL
python main.py analyze --url-list js_urls.txt             # a list of JS URLs
python main.py analyze --dir ./downloaded_js              # a local directory
python main.py analyze -f ./app.js                        # a single local file
```

### Common options (`hunt`)

| Option | Description |
| --- | --- |
| `-d, --domain` | Target domain to crawl (discovers `.js` automatically). |
| `-l, --list` | File of seed URLs — pages or `.js`, one per line (`-` reads stdin). |
| `--depth` | Crawl depth for link-following (default `2`; `0` = only the seeds). |
| `--max-pages` | Maximum number of pages to crawl (default `200`). |
| `--subs / --no-subs` | Include subdomains of the target in scope (default: include). |
| `--wayback` | Also pull historic `.js` URLs from the Wayback Machine. |
| `--offline` | Deterministic scan only — no AI call, no API key, no cost. |
| `--skip-libs` | Skip well-known libraries (jQuery, Bootstrap, ...) to save AI spend. |
| `-c, --concurrency` | Number of sources fetched/analyzed in parallel (default `5`). |
| `--proxy` | Route all HTTP through a proxy, e.g. `http://127.0.0.1:8080`. |
| `--insecure` | Skip TLS certificate verification. |
| `-H, --header` | Extra request header `'Name: Value'` (repeatable). |
| `-o, --output` | Output directory for reports (default `./reports`). |
| `--html` | Also write a styled HTML report per source, plus a batch index. |
| `-m, --model` | Model to use (defaults per provider). |
| `-v, --verbose` | Verbose logging. |

Run `python main.py hunt --help` for the full list.

## Output

For each run, JS-Oracle writes to the output directory (default `./reports`):

- `discovered_js.txt` — every `.js` URL that was found (one per line).
- `parameters.txt` — query-string parameter names seen during the crawl.
- `<source>.json` and `<source>.md` — per-file findings (endpoints, secrets,
  auth logic, suspicious patterns).
- `index.html` — a browsable batch report, when `--html` is used.

Findings are also printed to the terminal, ranked by severity.

## Responsible use

JS-Oracle is for authorized security testing only. Only run it against targets
you own or are explicitly permitted to test (for example, an in-scope bug bounty
program). You are responsible for how you use it.

## License

MIT — see [LICENSE](LICENSE).

"""js-oracle as an HTTP microservice (FastAPI).

Lets the scan-engine bridge call js-oracle over HTTP instead of spawning a
subprocess per file, so the AI layer can be scaled/replicated independently and
the caller no longer needs js-oracle's venv on the same box.

Run (from the js-oracle root, inside its .venv, with the same .env as the CLI):

    pip install -r requirements.txt -r requirements-service.txt
    uvicorn service:app --host 0.0.0.0 --port 8787

Then point the engine at it:

    export JS_ORACLE_MODE=http
    export JS_ORACLE_URL=http://127.0.0.1:8787

Endpoints
---------
GET  /health   -> {"status": "ok"}
POST /analyze  {url? | content?, domain?, model?, regex_endpoints?, use_cache?}
               -> merged findings dict
                  {analysis_summary, endpoints, secrets, auth_logic, suspicious_logic}

Security note: `content`/`url` are attacker-influenced target assets. They are
only ever analyzed (fetched + sent to the model as untrusted data, exactly as
the CLI does); this service does not execute them. Bind it to localhost or an
internal network — it exposes your model spend, so do not expose it publicly
without auth in front.
"""

from dotenv import load_dotenv

# Load .env before importing the analyzer so the provider client finds its key.
load_dotenv()

from fastapi import FastAPI, HTTPException          # noqa: E402
from pydantic import BaseModel, model_validator     # noqa: E402

from core.fetcher import JSFetcher                   # noqa: E402
from core.pipeline import analyze_source             # noqa: E402
from utils.logger import get_logger                  # noqa: E402

logger = get_logger("js-oracle-service")

app = FastAPI(title="js-oracle", version="0.1.0",
              description="AI-powered JavaScript analysis as a service.")


class AnalyzeRequest(BaseModel):
    url: str | None = None
    content: str | None = None
    domain: str = ""
    model: str | None = None
    regex_endpoints: bool = False
    use_cache: bool = True

    @model_validator(mode="after")
    def _need_a_source(self):
        if not (self.content and self.content.strip()) and not (self.url and self.url.strip()):
            raise ValueError("provide either 'content' or 'url'")
        return self


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "js-oracle"}


@app.post("/analyze")
def analyze(req: AnalyzeRequest) -> dict:
    """Analyze one JS source (raw content, or a URL to fetch) and return findings."""
    content = req.content
    if not content:
        try:
            content = JSFetcher().fetch_url(req.url)
        except Exception as exc:
            # A fetch failure is the caller's problem (bad/blocked URL), not ours.
            raise HTTPException(status_code=400, detail=f"fetch failed: {exc}")

    try:
        return analyze_source(
            content, req.domain, model=req.model,
            use_cache=req.use_cache, regex_endpoints=req.regex_endpoints)
    except Exception as exc:
        logger.error(f"analysis failed: {exc}")
        raise HTTPException(status_code=502, detail=f"analysis failed: {exc}")

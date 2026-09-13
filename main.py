from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pathlib import Path
import json
import datetime
import uuid
import hashlib
import os

app = FastAPI()

BASE_DIR = Path(__file__).parent

# DATA_DIR с fallback: /data (постоянный диск Amvera) → локальная папка
_env_data = os.environ.get("DATA_DIR")
if _env_data:
    _candidate = Path(_env_data)
    try:
        _candidate.mkdir(parents=True, exist_ok=True)
        _probe = _candidate / ".write_test"
        _probe.write_text("ok")
        _probe.unlink()
        DATA_DIR = _candidate
    except Exception:
        DATA_DIR = BASE_DIR / "data"
else:
    DATA_DIR = BASE_DIR / "data"

DATA_DIR.mkdir(parents=True, exist_ok=True)

VISITS_FILE  = DATA_DIR / "visits.jsonl"
COLLECT_FILE = DATA_DIR / "collect.jsonl"
EVENTS_FILE  = DATA_DIR / "events.jsonl"
RAW_FILE     = DATA_DIR / "raw.log"

ADMIN_TOKEN = "change-me-please"


def now_iso() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"


def append_jsonl(path: Path, obj: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")


def append_raw(line: str) -> None:
    with RAW_FILE.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def client_ip(request: Request) -> str:
    return (
        request.headers.get("cf-connecting-ip")
        or request.headers.get("x-real-ip")
        or (request.headers.get("x-forwarded-for", "").split(",")[0].strip() or None)
        or (request.client.host if request.client else "unknown")
    )


def request_fingerprint(request: Request) -> dict:
    h = request.headers
    header_blob = "|".join(f"{k.lower()}={v}" for k, v in h.items())
    fp = hashlib.sha256(header_blob.encode("utf-8", "ignore")).hexdigest()[:16]

    return {
        "ts": now_iso(),
        "method": request.method,
        "url": str(request.url),
        "path": request.url.path,
        "query": dict(request.query_params),
        "http_version": request.scope.get("http_version"),
        "scheme": request.url.scheme,
        "server": request.scope.get("server"),
        "client": {
            "ip": client_ip(request),
            "raw_host": request.client.host if request.client else None,
            "raw_port": request.client.port if request.client else None,
        },
        "headers": dict(h),
        "headers_ordered": list(h.items()),
        "cookies": dict(request.cookies),
        "header_fingerprint": fp,
        "user_agent": h.get("user-agent"),
        "accept_language": h.get("accept-language"),
        "accept_encoding": h.get("accept-encoding"),
        "referer": h.get("referer"),
        "origin": h.get("origin"),
        "cf": {
            "connecting_ip": h.get("cf-connecting-ip"),
            "ip_country": h.get("cf-ipcountry"),
            "ray": h.get("cf-ray"),
            "visitor": h.get("cf-visitor"),
        },
        "client_hints": {
            k: v for k, v in h.items() if k.lower().startswith("sec-ch-")
        },
    }


# ============================================================
#  Служебные роуты — объявляем их ПЕРВЫМИ
# ============================================================

@app.get("/_admin", response_class=PlainTextResponse)
async def admin(token: str = "", kind: str = "visits", limit: int = 20):
    if token != ADMIN_TOKEN:
        return PlainTextResponse("forbidden", status_code=403)

    files = {
        "visits":  VISITS_FILE,
        "collect": COLLECT_FILE,
        "events":  EVENTS_FILE,
    }
    path = files.get(kind, VISITS_FILE)
    if not path.exists():
        return PlainTextResponse(f"(пусто) {path}")

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    tail = lines[-limit:]

    out = []
    for ln in tail:
        try:
            obj = json.loads(ln)
            out.append(json.dumps(obj, ensure_ascii=False, indent=2))
        except Exception:
            out.append(ln)
    return PlainTextResponse("\n\n---\n\n".join(out))


@app.get("/_files", response_class=PlainTextResponse)
async def list_files(token: str = ""):
    """Показать, какие файлы есть в DATA_DIR и их размеры."""
    if token != ADMIN_TOKEN:
        return PlainTextResponse("forbidden", status_code=403)
    if not DATA_DIR.exists():
        return PlainTextResponse(f"DATA_DIR не существует: {DATA_DIR}")
    out = [f"DATA_DIR = {DATA_DIR}"]
    for p in sorted(DATA_DIR.iterdir()):
        out.append(f"{p.name}  {p.stat().st_size} bytes")
    return PlainTextResponse("\n".join(out))


@app.post("/collect")
async def collect(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {"_error": "invalid json"}

    rec = request_fingerprint(request)
    rec["type"] = "collect"
    rec["visit_id"] = request.cookies.get("visit_id")
    rec["data"] = body

    append_jsonl(COLLECT_FILE, rec)
    append_raw(
        f"{rec['ts']} COLLECT {rec['client']['ip']} "
        f"keys={list((body or {}).keys())[:10]}"
    )
    return JSONResponse({"ok": True})


# ============================================================
#  Главная страница и заглушка
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    rec = request_fingerprint(request)
    rec["type"] = "visit"
    append_jsonl(VISITS_FILE, rec)
    append_raw(f"{rec['ts']} VISIT {rec['client']['ip']} {rec['user_agent']}")

    html = (BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    resp = HTMLResponse(html)

    if "visit_id" not in request.cookies:
        vid = uuid.uuid4().hex
        resp.set_cookie(
            "visit_id", vid,
            max_age=60 * 60 * 24 * 365,
            httponly=False,
            samesite="lax",
            secure=True,
        )
    return resp


# ============================================================
#  Wildcard — ПОСЛЕДНИМ, и с исключением служебных путей
# ============================================================

@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
)
async def catch_all(full_path: str, request: Request):
    # Не перехватываем служебные роуты
    if full_path.startswith("_") or full_path == "collect":
        raise HTTPException(status_code=404)

    rec = request_fingerprint(request)
    rec["type"] = "other"
    rec["full_path"] = full_path
    try:
        raw = await request.body()
        if raw:
            rec["body_preview"] = raw[:4096].decode("utf-8", "replace")
    except Exception:
        pass

    append_jsonl(EVENTS_FILE, rec)
    append_raw(f"{rec['ts']} OTHER {rec['method']} /{full_path} {rec['client']['ip']}")

    html = (BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(html)
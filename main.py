from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pathlib import Path
import json
import datetime
import uuid
import hashlib

app = FastAPI()

BASE_DIR = Path(__file__).parent
import os
DATA_DIR = Path(os.environ.get("DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

# Отдельные файлы — удобнее потом фильтровать
VISITS_FILE    = DATA_DIR / "visits.jsonl"      # каждый GET / со всеми заголовками
COLLECT_FILE   = DATA_DIR / "collect.jsonl"     # POST от JS-сборщика
EVENTS_FILE    = DATA_DIR / "events.jsonl"      # всё остальное: ошибки, /favicon, и т.д.
RAW_FILE       = DATA_DIR / "raw.log"           # сырой лог строкой (на всякий случай)


def now_iso() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"


def append_jsonl(path: Path, obj: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")


def append_raw(line: str) -> None:
    with RAW_FILE.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def client_ip(request: Request) -> str:
    # За Cloudflare Tunnel реальный IP тут:
    return (
        request.headers.get("cf-connecting-ip")
        or request.headers.get("x-real-ip")
        or (request.headers.get("x-forwarded-for", "").split(",")[0].strip() or None)
        or (request.client.host if request.client else "unknown")
    )


def request_fingerprint(request: Request) -> dict:
    """
    Собираем всё, что видно на уровне HTTP — без JS.
    """
    h = request.headers
    # Стабильный fingerprint по заголовкам (порядок + значения)
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
        "headers_ordered": list(h.items()),   # порядок заголовков — тоже отпечаток
        "cookies": dict(request.cookies),
        "header_fingerprint": fp,
        "user_agent": h.get("user-agent"),
        "accept_language": h.get("accept-language"),
        "accept_encoding": h.get("accept-encoding"),
        "referer": h.get("referer"),
        "origin": h.get("origin"),
        # Cloudflare-специфичные
        "cf": {
            "connecting_ip": h.get("cf-connecting-ip"),
            "ip_country": h.get("cf-ipcountry"),
            "ray": h.get("cf-ray"),
            "visitor": h.get("cf-visitor"),
            "warp": h.get("cf-warp-tag-id"),
            "worker": h.get("cf-worker"),
        },
        # Client Hints (Chromium)
        "client_hints": {
            k: v for k, v in h.items() if k.lower().startswith("sec-ch-")
        },
    }


# ============================================================
#  Страница-заглушка
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    # Логируем визит
    rec = request_fingerprint(request)
    rec["type"] = "visit"
    append_jsonl(VISITS_FILE, rec)
    append_raw(f"{rec['ts']} VISIT {rec['client']['ip']} {rec['user_agent']}")

    html = (BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    resp = HTMLResponse(html)

    # Ставим идентификатор посещения в cookie, чтобы потом связать с POST /collect
    if "visit_id" not in request.cookies:
        vid = uuid.uuid4().hex
        resp.set_cookie(
            "visit_id", vid,
            max_age=60 * 60 * 24 * 365,
            httponly=False,      # пусть JS видит — пригодится для связи
            samesite="lax",
            secure=True,         # за HTTPS-туннелем всегда
        )
    return resp


# ============================================================
#  Приём данных от JS-сборщика
# ============================================================

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
#  Ловим любые другие пути — включая favicon, robots и т.п.
# ============================================================

@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
)
async def catch_all(full_path: str, request: Request):
    rec = request_fingerprint(request)
    rec["type"] = "other"
    rec["full_path"] = full_path
    # Тело, если оно есть (аккуратно, только первые 4 КБ)
    try:
        raw = await request.body()
        if raw:
            rec["body_preview"] = raw[:4096].decode("utf-8", "replace")
    except Exception:
        pass

    append_jsonl(EVENTS_FILE, rec)
    append_raw(f"{rec['ts']} OTHER {rec['method']} /{full_path} {rec['client']['ip']}")

    # Всё, кроме / и /collect, отдаём ту же заглушку
    html = (BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(html)


# ============================================================
#  Быстрый просмотр — только для вас, по токену
# ============================================================

ADMIN_TOKEN = "change-me-please"


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

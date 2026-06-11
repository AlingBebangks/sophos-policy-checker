"""Sophos XG Policy Checker — FastAPI entry point."""
import uuid
import time
from datetime import datetime
from fastapi import FastAPI, File, UploadFile, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from pathlib import Path

from .parser import parse
from .engine import run_all
from .checks.models import Severity

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))

app = FastAPI(title="Sophos Policy Checker", docs_url=None, redoc_url=None)

# In-memory report store: token -> (context_dict, expiry_timestamp)
# Context stores everything needed to re-render (findings, counts, stats, metadata).
_report_store: dict[str, tuple[dict, float]] = {}
_REPORT_TTL = 3600  # 1 hour


def _build_context(filename: str, raw: bytes) -> dict:
    cfg = parse(raw)
    findings = run_all(cfg)

    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1

    stats = {
        "firewall_rules": len(cfg.firewall_rules),
        "nat_rules": len(cfg.nat_rules),
        "vpn_ipsec": len(cfg.vpn_ipsec),
        "vpn_ssl": len(cfg.vpn_ssl),
        "syslog_servers": len(cfg.syslog_servers),
        "certificates": len(cfg.certificates),
        "raw_sections": {k: v for k, v in cfg.raw_sections.items()
                         if k not in {"FirewallRule", "NATRule", "IPsecPolicy",
                                      "SSLVPNPolicy", "SyslogServer", "Certificate",
                                      "Zone", "Services"}},
    }

    return {
        "filename": filename,
        "generated": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "findings": findings,
        "counts": counts,
        "stats": stats,
    }


def _prune_store() -> None:
    now = time.time()
    expired = [k for k, (_, exp) in _report_store.items() if now > exp]
    for k in expired:
        del _report_store[k]


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/analyze", response_class=HTMLResponse)
async def analyze(request: Request, config_file: UploadFile = File(...)):
    if not config_file.filename:
        return HTMLResponse("<h3>No file uploaded.</h3>", status_code=400)

    raw = await config_file.read()
    if len(raw) > 50 * 1024 * 1024:
        return HTMLResponse("<h3>File too large (max 50 MB).</h3>", status_code=413)

    try:
        ctx = _build_context(config_file.filename, raw)
    except ValueError as exc:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": str(exc),
        }, status_code=422)

    _prune_store()
    token = uuid.uuid4().hex
    _report_store[token] = (ctx, time.time() + _REPORT_TTL)

    return templates.TemplateResponse("report.html", {
        "request": request,
        "token": token,
        **ctx,
    })


@app.get("/report/{token}/pdf")
async def report_pdf(token: str):
    """Re-render the stored report as a downloadable PDF."""
    from weasyprint import HTML as WP_HTML

    entry = _report_store.get(token)
    if entry is None or time.time() > entry[1]:
        _report_store.pop(token, None)
        return HTMLResponse("<h3>Report expired or not found. Please re-upload your config.</h3>", status_code=404)

    ctx, _ = entry
    html_str = templates.get_template("report.html").render(
        request=None,
        token=token,
        pdf_mode=True,
        **ctx,
    )
    pdf_bytes = WP_HTML(string=html_str, base_url=str(BASE / "templates")).write_pdf()

    safe_name = ctx["filename"].replace(".xml", "").replace(" ", "_")
    disposition = f'attachment; filename="sophos-audit-{safe_name}.pdf"'

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": disposition},
    )


@app.get("/health")
async def health():
    return JSONResponse({"status": "ok"})

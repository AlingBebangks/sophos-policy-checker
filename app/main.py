"""Sophos XG Policy Checker — FastAPI entry point."""
import uuid
import time
from collections import deque
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, File, UploadFile, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader
from pathlib import Path

from .parser import parse
from .engine import run_all
from .checks.models import Severity

_SGT = timezone(timedelta(hours=8))

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))
# Raw Jinja2 env for PDF rendering (no request object required)
_jinja_env = Environment(loader=FileSystemLoader(str(BASE / "templates")))

app = FastAPI(title="Sophos Policy Checker", docs_url=None, redoc_url=None)

# In-memory report store: token -> (context_dict, expiry_timestamp)
_report_store: dict[str, tuple[dict, float]] = {}
_REPORT_TTL = 3600  # 1 hour

# ── Rate limiting (upload endpoint) ──────────────────────────────────────────
# Sliding-window: max 10 uploads per IP per 60 seconds. No external dependency.
_RATE_LIMIT    = 10
_RATE_WINDOW   = 60  # seconds
_rate_buckets: dict[str, deque] = {}


def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    bucket = _rate_buckets.setdefault(ip, deque())
    # Drop timestamps outside the window
    while bucket and bucket[0] < now - _RATE_WINDOW:
        bucket.popleft()
    if len(bucket) >= _RATE_LIMIT:
        return True
    bucket.append(now)
    return False


def _risk_score(counts: dict) -> int:
    """0–100 risk score. Higher = worse."""
    score = (counts["Critical"] * 25 + counts["High"] * 10 +
             counts["Medium"] * 4  + counts["Low"] * 1)
    return min(score, 100)


def _overall_rating(counts: dict) -> str:
    if counts["Critical"] > 0: return "Critical"
    if counts["High"]     > 0: return "High"
    if counts["Medium"]   > 0: return "Medium"
    if counts["Low"]      > 0: return "Low"
    return "Passed"


def _exec_summary(findings: list, counts: dict) -> dict:
    """Generate executive summary text from findings."""
    rating = _overall_rating(counts)
    score  = _risk_score(counts)

    posture_map = {
        "Critical": "The firewall presents immediate, exploitable risks. Urgent remediation is required before this device is considered production-safe.",
        "High":     "The configuration contains serious weaknesses that significantly increase exposure. Remediation should be prioritised within the current change cycle.",
        "Medium":   "The configuration meets a basic security baseline but has notable gaps that should be addressed in the near term.",
        "Low":      "The configuration is broadly sound. Minor hardening improvements are recommended.",
        "Passed":   "No issues were detected. Continue to review configurations periodically.",
    }

    top = [f for f in findings if f.severity.value in ("Critical", "High")][:5]
    immediate = []
    for f in top:
        ac = len(f.affected_rules) or len(f.affected)
        obj = f"{ac} rule{'s' if ac != 1 else ''}" if ac else "configuration"
        immediate.append(f"{f.title} — affects {obj}")

    # Split policy vs config counts
    policy_cats = {"Firewall Rules", "NAT Rules", "VPN — IPSec", "Administration", "Logging"}
    policy_findings  = [f for f in findings if f.category in policy_cats]
    config_findings  = [f for f in findings if f.category not in policy_cats]

    policy_counts = {s: 0 for s in ("Critical","High","Medium","Low","Info")}
    config_counts = {s: 0 for s in ("Critical","High","Medium","Low","Info")}
    for f in policy_findings:
        policy_counts[f.severity.value] += 1
    for f in config_findings:
        config_counts[f.severity.value] += 1

    return {
        "rating":         rating,
        "score":          score,
        "posture":        posture_map[rating],
        "immediate":      immediate,
        "total":          len(findings),
        "policy_counts":  policy_counts,
        "config_counts":  config_counts,
        "policy_total":   len(policy_findings),
        "config_total":   len(config_findings),
    }


def _build_context(filename: str, raw: bytes) -> dict:
    cfg = parse(raw)
    findings = run_all(cfg)

    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1

    stats = {
        "firewall_rules": len(cfg.firewall_rules),
        "nat_rules":      len(cfg.nat_rules),
        "vpn_ipsec":      len(cfg.vpn_ipsec),
        "vpn_ssl":        len(cfg.vpn_ssl),
        "syslog_servers": len(cfg.syslog_servers),
        "certificates":   len(cfg.certificates),
        "raw_sections":   {k: v for k, v in cfg.raw_sections.items()
                           if k not in {"FirewallRule", "NATRule", "IPsecPolicy",
                                        "SSLVPNPolicy", "SyslogServer", "Certificate",
                                        "Zone", "Services"}},
    }

    return {
        "filename":  filename,
        "generated": datetime.now(_SGT).strftime("%Y-%m-%d %H:%M SGT"),
        "findings":  findings,
        "counts":    counts,
        "stats":     stats,
        "exec":      _exec_summary(findings, counts),
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
    client_ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(client_ip):
        return HTMLResponse(
            "<h3>Too many requests. Please wait before uploading again.</h3>",
            status_code=429,
        )

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
        "pdf_mode": False,
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
    html_str = _jinja_env.get_template("report.html").render(
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

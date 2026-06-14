"""Shared finding model."""
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_COLOR = {
    Severity.CRITICAL: "#c0392b",
    Severity.HIGH: "#e67e22",
    Severity.MEDIUM: "#f1c40f",
    Severity.LOW: "#2980b9",
    Severity.INFO: "#7f8c8d",
}


@dataclass
class Finding:
    severity: Severity
    category: str
    title: str
    detail: str
    recommendation: str
    references: list[str] = field(default_factory=list)
    affected: list[str] = field(default_factory=list)
    location: str = ""
    affected_rules: list[dict] = field(default_factory=list)
    # ── Scoring axes (CVSS-inspired, set per finding) ──────────────────────
    exploitability: str = "High"    # High / Medium / Low
    impact_scope:   str = "Network" # Network / Host / Local
    exposure:       str = "External"# External / Internal / Adjacent
    # ── Real-world attack examples (injected by engine in deep mode) ────────
    real_world_examples: list[str] = field(default_factory=list)


# ── Per-finding score ─────────────────────────────────────────────────────────
_EXPLOIT_W  = {"High": 1.0, "Medium": 0.7, "Low": 0.4}
_SCOPE_W    = {"Network": 1.0, "Host": 0.7, "Local": 0.4}
_EXPOSURE_W = {"External": 1.0, "Adjacent": 0.7, "Internal": 0.4}
_SEV_BASE   = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Info": 0}


def finding_score(f: Finding) -> float:
    base = _SEV_BASE.get(f.severity.value, 0)
    mult = (
        _EXPLOIT_W.get(f.exploitability, 1.0)
        * _SCOPE_W.get(f.impact_scope, 1.0)
        * _EXPOSURE_W.get(f.exposure, 1.0)
    )
    return round(base * mult, 1)

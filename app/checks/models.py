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
    # ── Detectability modifier: does logging capture this attack path? ──────
    # "Logged"   → logs exist, attack is detectable → score reduced 10%
    # "Unknown"  → logging state unclear            → no adjustment
    # "Unlogged" → no logging on affected rules     → score increased 20%
    detectability: str = "Unknown"  # Logged / Unknown / Unlogged
    # ── Real-world attack examples (injected by engine in deep mode) ────────
    real_world_examples: list[str] = field(default_factory=list)


# ── Per-finding score (CVSS / Nipper aligned, 0–10) ──────────────────────────
# Base mirrors CVSS v3 severity thresholds:
#   Critical ≥ 9.0 · High 7.0–8.9 · Medium 4.0–6.9 · Low 2.0–3.9
# Axis multipliers use a CVSS-like range (0.70–1.0) so severity is the primary
# driver and axes are modifiers — avoids Nipper's behaviour where a Low finding
# with bad axes scores higher than a Medium finding with good axes.
_SEV_BASE   = {"Critical": 9.0, "High": 7.0, "Medium": 4.0, "Low": 2.0, "Info": 0.0}

# Attack Complexity (exploitability): how hard is it to exploit?
# High exploit = Low complexity (easy) = ×1.0
_EXPLOIT_W  = {"High": 1.00, "Medium": 0.85, "Low": 0.70}

# Impact magnitude: how far does a successful exploit reach?
_SCOPE_W    = {"Network": 1.00, "Host": 0.85, "Local": 0.70}

# Attack Vector: how close must the attacker be?
# External = network-reachable (worst), Adjacent = same L2/segment, Internal = local only
_EXPOSURE_W = {"External": 1.00, "Adjacent": 0.85, "Internal": 0.70}

# Temporal modifier (detectability) — mirrors CVSS temporal score ±5%
# Logged   → attack leaves evidence, easier to detect and respond   → −5%
# Unknown  → logging state unclear                                  → ±0%
# Unlogged → no evidence, dwell time extended                       → +5%
_DETECT_W   = {"Logged": 0.95, "Unknown": 1.00, "Unlogged": 1.05}


def finding_score(f: Finding) -> float:
    base = _SEV_BASE.get(f.severity.value, 0.0)
    raw = (
        base
        * _EXPLOIT_W.get(f.exploitability, 1.0)
        * _SCOPE_W.get(f.impact_scope, 1.0)
        * _EXPOSURE_W.get(f.exposure, 1.0)
        * _DETECT_W.get(f.detectability, 1.0)
    )
    return round(min(raw, 10.0), 1)

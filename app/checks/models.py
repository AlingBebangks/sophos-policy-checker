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

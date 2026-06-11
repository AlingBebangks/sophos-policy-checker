"""Run all policy checks and return sorted findings."""
from .checks.models import Finding, SEVERITY_ORDER
from .checks import firewall_rules, vpn, admin, logging_checks, nat
from .parser import SophosConfig


def run_all(cfg: SophosConfig) -> list[Finding]:
    findings: list[Finding] = []
    for module in (firewall_rules, vpn, admin, logging_checks, nat):
        findings.extend(module.run(cfg))
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return findings

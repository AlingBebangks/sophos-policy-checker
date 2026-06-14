"""Run all policy and configuration checks, return sorted findings."""
from .checks.models import Finding, SEVERITY_ORDER
from .checks import (
    # Policy checks
    firewall_rules, vpn, admin, logging_checks, nat,
    # Config checks
    cfg_system, cfg_auth, cfg_certificates, cfg_network, cfg_threat, cfg_email,
    cfg_ports,
)
from .checks.framework_refs import enrich
from .checks.real_world_cases import match as _match_cases
from .parser import SophosConfig


def run_all(cfg: SophosConfig) -> list[Finding]:
    findings: list[Finding] = []
    for module in (
        # Policy
        firewall_rules, vpn, admin, logging_checks, nat,
        # Configuration hardening
        cfg_system, cfg_auth, cfg_certificates, cfg_network, cfg_threat, cfg_email,
        cfg_ports,
    ):
        findings.extend(module.run(cfg))
    # Append NIST SP 800-53 Rev 5 and CIS Controls v8 references to every finding.
    findings = [enrich(f) for f in findings]
    # Attach real-world examples to every finding (used when deep_mode=True).
    for f in findings:
        f.real_world_examples = _match_cases(f.title)
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return findings

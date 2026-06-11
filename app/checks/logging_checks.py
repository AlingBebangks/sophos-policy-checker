"""Logging and monitoring checks."""
from .models import Finding, Severity


def run(cfg) -> list[Finding]:
    findings: list[Finding] = []

    # ── Syslog ────────────────────────────────────────────────────────────────
    if not cfg.syslog_servers:
        findings.append(Finding(
            severity=Severity.HIGH,
            category="Logging",
            title="No syslog server configured",
            detail=(
                "Without a remote syslog or SIEM destination, firewall logs are stored "
                "only locally. Local logs can be lost on device failure or tampering, "
                "and are unavailable for centralised alerting."
            ),
            recommendation=(
                "Configure at least one syslog server or SIEM collector. "
                "Forward all firewall, IPS, and authentication logs to it."
            ),
            references=["CIS Sophos Benchmark §3.1", "NIST SP 800-92"],
        ))
    elif len(cfg.syslog_servers) == 1:
        findings.append(Finding(
            severity=Severity.LOW,
            category="Logging",
            title="Only one syslog server configured",
            detail="A single syslog destination is a single point of failure for log collection.",
            recommendation="Configure a secondary syslog/SIEM destination for redundancy.",
        ))

    # ── IPS ───────────────────────────────────────────────────────────────────
    ips = cfg.ips_settings
    if not ips:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="Logging",
            title="IPS settings not found",
            detail="IPS configuration was not detected. IPS may be disabled or unconfigured.",
            recommendation=(
                "Ensure IPS is enabled on all relevant interfaces. "
                "Apply an appropriate IPS policy to firewall rules for inbound traffic."
            ),
        ))
    else:
        status = str(ips.get("Status", ips.get("Enable", ""))).lower()
        if status in ("disable", "disabled", "0", "false", "off"):
            findings.append(Finding(
                severity=Severity.HIGH,
                category="Logging",
                title="Intrusion Prevention System (IPS) is disabled",
                detail="IPS is explicitly disabled. Intrusion attempts will not be detected or blocked.",
                recommendation=(
                    "Enable IPS and assign an IPS policy to all firewall rules handling "
                    "untrusted traffic (WAN-to-LAN, WAN-to-DMZ)."
                ),
            ))

    # ── DoS Protection ────────────────────────────────────────────────────────
    dos = cfg.dos_settings
    if not dos:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="Logging",
            title="DoS Protection settings not found",
            detail="DoS/DDoS protection configuration was not detected in the backup.",
            recommendation="Verify DoS protection is enabled and tuned for your environment.",
        ))
    else:
        status = str(dos.get("Status", dos.get("Enable", ""))).lower()
        if status in ("disable", "disabled", "0", "false", "off"):
            findings.append(Finding(
                severity=Severity.HIGH,
                category="Logging",
                title="DoS Protection is disabled",
                detail="Denial-of-service protection is explicitly off, leaving the network exposed to volumetric attacks.",
                recommendation="Enable DoS protection policies for all WAN-facing interfaces.",
            ))

    return findings

"""Logging and monitoring checks."""
from .models import Finding, Severity
from .utils import v as _v, off as _off


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
                "Forward all firewall, IPS, and authentication logs to it. "
                "No remote logging enables MITRE ATT&CK T1070 (Indicator Removal) — "
                "an attacker can clear local logs to erase evidence with no offsite copy. "
                "Also facilitates T1562.006 (Impair Defenses: Indicator Blocking). "
                "Aligns with OWASP A09:2021 – Security Logging and Monitoring Failures."
            ),
            location=(
                "Firewall → Log settings → Syslog servers\n"
                "→ Click 'Add' → enter server IP, port (514 UDP or 6514 TLS), "
                "facility and severity → Save"
            ),
            references=[
                "MITRE ATT&CK T1070 – Indicator Removal",
                "MITRE ATT&CK T1562.006 – Impair Defenses: Indicator Blocking",
                "OWASP A09:2021 – Security Logging and Monitoring Failures",
                "CIS Control 8.2 – Collect Audit Logs",
                "CIS Control 8.9 – Centralize Audit Logs",
                "NIST SP 800-92 – Guide to Computer Security Log Management",
                "CIS Sophos Benchmark §3.1",
            ],
        ))
    elif len(cfg.syslog_servers) == 1:
        findings.append(Finding(
            severity=Severity.LOW,
            category="Logging",
            title="Only one syslog server configured",
            detail="A single syslog destination is a single point of failure for log collection.",
            recommendation=(
                "Configure a secondary syslog/SIEM destination for redundancy. "
                "Loss of the single syslog server creates a log gap that enables "
                "MITRE ATT&CK T1070 (Indicator Removal) by circumstance. "
                "Aligns with OWASP A09:2021 – Security Logging and Monitoring Failures."
            ),
            references=[
                "MITRE ATT&CK T1070 – Indicator Removal",
                "OWASP A09:2021 – Security Logging and Monitoring Failures",
                "CIS Control 8.9 – Centralize Audit Logs",
            ],
            location=(
                "Firewall → Log settings → Syslog servers\n"
                "→ Click 'Add' to add a second syslog server"
            ),
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
                "Apply an appropriate IPS policy to firewall rules for inbound traffic. "
                "Without IPS, MITRE ATT&CK T1190 (Exploit Public-Facing Application) and "
                "T1203 (Exploitation for Client Execution) succeed silently. "
                "Aligns with OWASP A06:2021 – Vulnerable and Outdated Components "
                "(IPS detects exploitation of known CVEs)."
            ),
            references=[
                "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                "MITRE ATT&CK T1203 – Exploitation for Client Execution",
                "OWASP A06:2021 – Vulnerable and Outdated Components",
                "CIS Control 13.3 – Deploy a Network Intrusion Detection Solution",
            ],
            location=(
                "Firewall → Rules and policies → Firewall rules\n"
                "→ Edit each WAN-facing rule → under 'Security features' enable IPS "
                "and select an IPS policy → Save"
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
                    "untrusted traffic (WAN-to-LAN, WAN-to-DMZ). "
                    "Disabled IPS allows MITRE ATT&CK T1190 (Exploit Public-Facing Application) "
                    "and T1203 (Exploitation for Client Execution) to proceed undetected. "
                    "Aligns with OWASP A06:2021 – Vulnerable and Outdated Components."
                ),
                references=[
                    "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                    "MITRE ATT&CK T1203 – Exploitation for Client Execution",
                    "OWASP A06:2021 – Vulnerable and Outdated Components",
                    "CIS Control 13.3 – Deploy a Network Intrusion Detection Solution",
                    "NIST SP 800-94 – Guide to Intrusion Detection and Prevention Systems",
                ],
                location=(
                    "Intrusion prevention → IPS policies\n"
                    "→ Ensure at least one policy exists, then:\n"
                    "Firewall → Rules and policies → Firewall rules\n"
                    "→ Edit each WAN-facing rule → enable IPS and assign the policy → Save"
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
            recommendation=(
                "Verify DoS protection is enabled and tuned for your environment. "
                "Absent DoS protection enables MITRE ATT&CK T1499 (Endpoint Denial of Service) "
                "and T1498 (Network Denial of Service). "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            references=[
                "MITRE ATT&CK T1499 – Endpoint Denial of Service",
                "MITRE ATT&CK T1498 – Network Denial of Service",
                "OWASP A05:2021 – Security Misconfiguration",
                "CIS Control 13.8 – Deploy Network Traffic Filtering Controls",
            ],
            location=(
                "Firewall → Rules and policies → DoS and spoof protection\n"
                "→ Review and enable DoS rules for WAN-facing interfaces"
            ),
        ))
    else:
        status = str(dos.get("Status", dos.get("Enable", ""))).lower()
        if status in ("disable", "disabled", "0", "false", "off"):
            findings.append(Finding(
                severity=Severity.HIGH,
                category="Logging",
                title="DoS Protection is disabled",
                detail="Denial-of-service protection is explicitly off, leaving the network exposed to volumetric attacks.",
                recommendation=(
                    "Enable DoS protection policies for all WAN-facing interfaces. "
                    "Disabled DoS protection enables MITRE ATT&CK T1499 (Endpoint Denial of Service) "
                    "and T1498 (Network Denial of Service). "
                    "Aligns with OWASP A05:2021 – Security Misconfiguration."
                ),
                references=[
                    "MITRE ATT&CK T1499 – Endpoint Denial of Service",
                    "MITRE ATT&CK T1498 – Network Denial of Service",
                    "OWASP A05:2021 – Security Misconfiguration",
                    "CIS Control 13.8 – Deploy Network Traffic Filtering Controls",
                ],
                location=(
                    "Firewall → Rules and policies → DoS and spoof protection\n"
                    "→ Enable DoS protection and configure flood thresholds for WAN interfaces"
                ),
            ))

    return findings

"""Config checks — Threat protection (IPS, AV, Sandstorm, Web filter, App control, SSL inspection).

MITRE ATT&CK and OWASP references are included in each finding's recommendation and references fields.
"""
from .models import Finding, Severity

_S = "Config — Threat Protection"


def _v(d: dict, *keys: str) -> str:
    for k in keys:
        v = d.get(k, "")
        if v:
            return str(v).strip()
    return ""


def _off(val: str) -> bool:
    return val.lower() in ("disable", "disabled", "0", "false", "off", "no", "")


def run(cfg) -> list[Finding]:
    findings: list[Finding] = []

    # ── IPS Policies ─────────────────────────────────────────────────────────
    if not cfg.ips_policies:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="No IPS policies found",
            detail="IPS policies could not be detected. Without IPS, exploit attempts traverse the firewall undetected.",
            recommendation=(
                "Create and apply IPS policies to all firewall rules handling untrusted traffic. "
                "No IPS means MITRE ATT&CK T1190 (Exploit Public-Facing Application) and "
                "T1203 (Exploitation for Client Execution) succeed without detection or prevention. "
                "Aligns with OWASP A06:2021 – Vulnerable and Outdated Components."
            ),
            references=[
                "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                "MITRE ATT&CK T1203 – Exploitation for Client Execution",
                "OWASP A06:2021 – Vulnerable and Outdated Components",
                "CIS Control 13.3 – Deploy a Network Intrusion Detection Solution",
                "NIST SP 800-94 – Guide to IDS/IPS Systems",
            ],
            location="Intrusion prevention → IPS policies → Create policy → Apply to firewall rules",
        ))
    else:
        rules_without_ips = [
            r.get("name", f"Rule #{r.get('policy_index','?')}")
            for r in cfg.firewall_rules
            if r.get("action", "").lower() in ("accept", "allow")
            and not r.get("ips_policy")
        ]
        wan_rules_no_ips = [
            r.get("name", f"Rule #{r.get('policy_index','?')}")
            for r in cfg.firewall_rules
            if r.get("action", "").lower() in ("accept", "allow")
            and not r.get("ips_policy")
            and any(z.lower() in ("wan", "internet", "untrust", "external")
                    for z in r.get("src_zones", []))
        ]
        if wan_rules_no_ips:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=_S,
                title="WAN-facing accept rules without an IPS policy",
                detail="Accept rules sourced from the WAN zone have no IPS policy assigned. Exploit traffic passes through without inspection.",
                recommendation=(
                    "Attach an IPS policy to every accept rule that handles WAN-originated traffic. "
                    "Unprotected WAN rules are the primary entry point for MITRE ATT&CK T1190 "
                    "(Exploit Public-Facing Application) — every unpatched CVE is exploitable without IPS blocking it. "
                    "Aligns with OWASP A06:2021 – Vulnerable and Outdated Components."
                ),
                references=[
                    "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                    "MITRE ATT&CK T1203 – Exploitation for Client Execution",
                    "MITRE ATT&CK Mitigation M1031 – Network Intrusion Prevention",
                    "OWASP A06:2021 – Vulnerable and Outdated Components",
                    "CIS Control 13.3 – Deploy a Network Intrusion Detection Solution",
                ],
                location=(
                    "Firewall → Rules and policies → Firewall rules\n"
                    "→ Edit rule → Security features → assign IPS policy → Save"
                ),
                affected=wan_rules_no_ips,
            ))
        elif rules_without_ips:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=_S,
                title="Accept rules without an IPS policy assigned",
                detail="These rules allow traffic without IPS inspection.",
                recommendation=(
                    "Review and assign appropriate IPS policies. "
                    "Aligns with MITRE ATT&CK Mitigation M1031 (Network Intrusion Prevention) and "
                    "CIS Control 13.3."
                ),
                references=[
                    "MITRE ATT&CK Mitigation M1031 – Network Intrusion Prevention",
                    "CIS Control 13.3 – Deploy a Network Intrusion Detection Solution",
                ],
                location="Firewall → Rules and policies → Edit rule → Security features → assign IPS → Save",
                affected=rules_without_ips,
            ))

    # ── Antivirus ─────────────────────────────────────────────────────────────
    av = cfg.av_settings
    if not av:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="Antivirus/malware protection settings not found",
            detail="AV configuration was not detected. File-based malware scanning may be disabled.",
            recommendation=(
                "Enable malware scanning on HTTP, HTTPS, FTP, SMTP, and POP3 proxies. "
                "No AV scanning enables MITRE ATT&CK T1204.002 (User Execution: Malicious File) — "
                "malware-laden downloads pass through uninspected. "
                "Aligns with OWASP A06:2021 – Vulnerable and Outdated Components."
            ),
            references=[
                "MITRE ATT&CK T1204.002 – User Execution: Malicious File",
                "MITRE ATT&CK T1566.001 – Phishing: Spearphishing Attachment",
                "OWASP A06:2021 – Vulnerable and Outdated Components",
                "CIS Control 10.1 – Deploy and Maintain Anti-Malware Software",
            ],
            location="Web → Malware protection → Enable AV scanning\nEmail → Antivirus → Enable",
        ))
    else:
        status = _v(av, "Status", "Enable", "Enabled")
        if _off(status):
            findings.append(Finding(
                severity=Severity.HIGH,
                category=_S,
                title="Antivirus scanning is disabled",
                detail="Malware scanning is explicitly turned off. Infected files can traverse the firewall without detection.",
                recommendation=(
                    "Enable AV scanning for all applicable protocols (HTTP, HTTPS, FTP, SMTP, POP3). "
                    "Disabled AV enables MITRE ATT&CK T1204.002 (User Execution: Malicious File) and "
                    "T1566.001 (Spearphishing Attachment). "
                    "Aligns with OWASP A06:2021 – Vulnerable and Outdated Components."
                ),
                references=[
                    "MITRE ATT&CK T1204.002 – User Execution: Malicious File",
                    "MITRE ATT&CK T1566.001 – Phishing: Spearphishing Attachment",
                    "OWASP A06:2021 – Vulnerable and Outdated Components",
                    "CIS Control 10.1 – Deploy and Maintain Anti-Malware Software",
                ],
                location="Web → Malware protection → Enable AV\nEmail → Antivirus → Enable",
            ))
        dual_scan = _v(av, "DualScan", "DualAV", "SecondaryEngine")
        if _off(dual_scan):
            findings.append(Finding(
                severity=Severity.INFO,
                category=_S,
                title="Dual-engine AV scanning not enabled",
                detail="Single-engine scanning has lower detection rates than dual-engine. Dual scan increases coverage.",
                recommendation="Enable dual-engine (Sophos + secondary) AV scanning if licensed.",
                references=["CIS Control 10.1 – Deploy and Maintain Anti-Malware Software"],
                location="Web → Malware protection → enable Dual scan option",
            ))

    # ── Sandstorm ─────────────────────────────────────────────────────────────
    sandbox = cfg.sandbox_settings
    if not sandbox:
        findings.append(Finding(
            severity=Severity.LOW,
            category=_S,
            title="Sandstorm (cloud sandbox) not configured",
            detail="Sandstorm detonates suspicious files in a cloud sandbox to detect zero-day malware that bypasses signature-based AV.",
            recommendation=(
                "Enable Sophos Sandstorm for HTTP/HTTPS and email if licensed. "
                "Without sandboxing, MITRE ATT&CK T1027 (Obfuscated Files) and zero-day payloads "
                "that evade signatures pass through. "
                "Aligns with OWASP A06:2021 – Vulnerable and Outdated Components."
            ),
            references=[
                "MITRE ATT&CK T1027 – Obfuscated Files or Information",
                "MITRE ATT&CK T1059 – Command and Scripting Interpreter",
                "OWASP A06:2021 – Vulnerable and Outdated Components",
            ],
            location="Web → Malware protection → Sandstorm → Enable\nEmail → Sandstorm → Enable",
        ))
    else:
        status = _v(sandbox, "Status", "Enable", "Enabled", "State")
        if _off(status):
            findings.append(Finding(
                severity=Severity.LOW,
                category=_S,
                title="Sandstorm (cloud sandbox) is disabled",
                detail="Zero-day and unknown malware will not be sandboxed for analysis.",
                recommendation=(
                    "Enable Sandstorm cloud sandboxing if licensed. "
                    "Disabled sandboxing allows MITRE ATT&CK T1027 (Obfuscated Files) to bypass detection. "
                    "Aligns with OWASP A06:2021 – Vulnerable and Outdated Components."
                ),
                references=[
                    "MITRE ATT&CK T1027 – Obfuscated Files or Information",
                    "OWASP A06:2021 – Vulnerable and Outdated Components",
                ],
                location="Web → Malware protection → Sandstorm → Enable → Apply",
            ))

    # ── Web Filtering ─────────────────────────────────────────────────────────
    if not cfg.web_filter:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="No web filter policies found",
            detail="Without web filtering, users can browse malicious, phishing, or policy-violating sites freely.",
            recommendation=(
                "Create web filter policies and apply them to relevant firewall rules. "
                "No web filtering allows MITRE ATT&CK T1566.002 (Spearphishing Link) and "
                "T1189 (Drive-by Compromise). "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            references=[
                "MITRE ATT&CK T1566.002 – Phishing: Spearphishing Link",
                "MITRE ATT&CK T1189 – Drive-by Compromise",
                "OWASP A05:2021 – Security Misconfiguration",
                "CIS Control 9.3 – Maintain and Enforce Network-Based URL Filters",
            ],
            location="Web → Policies → Create web filter policy → Apply to firewall rules",
        ))
    else:
        rules_without_wf = [
            r.get("name", f"Rule #{r.get('policy_index','?')}")
            for r in cfg.firewall_rules
            if r.get("action", "").lower() in ("accept", "allow")
            and not r.get("web_filter")
            and any(z.lower() in ("lan", "internal", "trust", "users")
                    for z in r.get("src_zones", []))
        ]
        if rules_without_wf:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=_S,
                title="LAN-sourced accept rules without web filter policy",
                detail="Internal users can browse without web category filtering or malicious URL blocking.",
                recommendation=(
                    "Assign a web filter policy to all outbound rules from internal zones. "
                    "Unfiltered outbound allows MITRE ATT&CK T1566.002 (Spearphishing Link) and "
                    "T1189 (Drive-by Compromise) to succeed. "
                    "Aligns with OWASP A05:2021 – Security Misconfiguration."
                ),
                references=[
                    "MITRE ATT&CK T1566.002 – Phishing: Spearphishing Link",
                    "MITRE ATT&CK T1189 – Drive-by Compromise",
                    "OWASP A05:2021 – Security Misconfiguration",
                    "CIS Control 9.3 – Maintain and Enforce Network-Based URL Filters",
                ],
                location=(
                    "Firewall → Rules and policies → Firewall rules\n"
                    "→ Edit rule → Security features → assign Web filter policy → Save"
                ),
                affected=rules_without_wf,
            ))

    # ── Application Control ───────────────────────────────────────────────────
    if not cfg.app_control:
        findings.append(Finding(
            severity=Severity.LOW,
            category=_S,
            title="No application control policies found",
            detail="Without app control, high-risk applications (P2P, anonymisers, shadow IT) can operate freely.",
            recommendation=(
                "Create application filter policies to block high-risk application categories. "
                "Unrestricted app usage enables MITRE ATT&CK T1048 (Exfiltration Over Alternative Protocol) "
                "and T1071 (Application Layer Protocol) for C2. "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            references=[
                "MITRE ATT&CK T1048 – Exfiltration Over Alternative Protocol",
                "MITRE ATT&CK T1071 – Application Layer Protocol",
                "OWASP A05:2021 – Security Misconfiguration",
                "CIS Control 9.2 – Ensure Only Approved Ports/Services/Protocols Are Running",
            ],
            location="Firewall → Rules and policies → Application filter → Create policy → Apply to firewall rules",
        ))

    # ── SSL/TLS Inspection ────────────────────────────────────────────────────
    ssl = cfg.ssl_inspection
    if not ssl:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="SSL/TLS inspection not configured",
            detail=(
                "Without HTTPS inspection, threats hidden inside encrypted traffic (malware C2, data exfiltration, "
                "phishing) bypass all content scanning."
            ),
            recommendation=(
                "Configure SSL/TLS inspection with a trusted internal CA certificate deployed to endpoints. "
                "No TLS inspection enables MITRE ATT&CK T1573 (Encrypted Channel) — "
                "C2 beacons over HTTPS and encrypted malware downloads bypass gateway AV, IPS, and web filter. "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            references=[
                "MITRE ATT&CK T1573 – Encrypted Channel",
                "MITRE ATT&CK T1048.002 – Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
                "OWASP A05:2021 – Security Misconfiguration",
                "CIS Control 13.7 – Deploy a Host-Based Intrusion Detection Solution",
            ],
            location="Web → SSL/TLS inspection → Create inspection rule → Apply to firewall rules",
        ))
    else:
        status = _v(ssl, "Status", "Enable", "Enabled", "State")
        if _off(status):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=_S,
                title="SSL/TLS inspection is disabled",
                detail="Encrypted traffic is not inspected. Malware, exfiltration, and phishing via HTTPS bypass all gateway controls.",
                recommendation=(
                    "Enable SSL/TLS inspection and deploy the inspection CA certificate to managed endpoints. "
                    "Disabled TLS inspection enables MITRE ATT&CK T1573 (Encrypted Channel) — "
                    "every HTTPS request is a blind spot for AV, IPS, and web filter. "
                    "Aligns with OWASP A05:2021 – Security Misconfiguration."
                ),
                references=[
                    "MITRE ATT&CK T1573 – Encrypted Channel",
                    "MITRE ATT&CK T1573.002 – Encrypted Channel: Asymmetric Cryptography",
                    "OWASP A05:2021 – Security Misconfiguration",
                ],
                location="Web → SSL/TLS inspection → Enable → Apply",
            ))

    # ── DoS / Flood Protection ────────────────────────────────────────────────
    dos = cfg.dos_settings
    if not dos:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="DoS/flood protection settings not found",
            detail=(
                "No DoS protection configuration was detected. Without flood protection, "
                "the firewall may be susceptible to SYN flood, UDP flood, and ICMP flood attacks "
                "that exhaust connection tables and cause service interruption."
            ),
            recommendation=(
                "Enable DoS protection under Firewall → Flood protection. Configure SYN flood, "
                "UDP flood, and ICMP flood thresholds appropriate for your environment. "
                "Aligns with MITRE ATT&CK T1498 (Network Denial of Service) and T1499 (Endpoint DoS). "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            references=[
                "MITRE ATT&CK T1498 – Network Denial of Service",
                "MITRE ATT&CK T1499 – Endpoint Denial of Service",
                "OWASP A05:2021 – Security Misconfiguration",
                "NIST SP 800-53 Rev 5 SC-5 – Denial-of-Service Protection",
                "CIS Controls v8 – 13.4 Perform Traffic Filtering Between Network Segments",
            ],
            location="Firewall → Flood protection → Enable SYN/UDP/ICMP flood protection → Apply",
        ))
    else:
        # Check each flood type's Apply Flag
        _FLOOD_TYPES = [
            ("SYNFlood",   "SYNFlood",   "SYN"),
            ("UDPFlood",   "UDPFlood",   "UDP"),
            ("ICMPFlood",  "ICMPFlood",  "ICMP"),
            ("IPFlood",    "IPFlood",    "IP"),
        ]
        disabled_floods: list[str] = []
        for key, label, proto in _FLOOD_TYPES:
            section = dos.get(key, {})
            if not isinstance(section, dict):
                continue
            apply_flag = section.get("ApplyFlag") or section.get("Enable") or section.get("Status") or ""
            if _off(str(apply_flag)):
                disabled_floods.append(proto)
            # Also check flat-key layout (some firmware versions)
            flat_flag = dos.get(f"{key}ApplyFlag") or dos.get(f"{key}Enable") or ""
            if flat_flag and _off(str(flat_flag)) and proto not in disabled_floods:
                disabled_floods.append(proto)

        # Check top-level enable flag
        top_flag = _v(dos, "Enable", "Status", "Enabled", "FloodProtection")
        if _off(top_flag) and not disabled_floods:
            disabled_floods = ["SYN", "UDP", "ICMP", "IP"]  # all implicitly off

        if disabled_floods:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=_S,
                title=f"Flood protection disabled for: {', '.join(disabled_floods)}",
                detail=(
                    f"The following flood protection types are disabled or have ApplyFlag set to off: "
                    f"{', '.join(disabled_floods)}. "
                    "Without these controls, an attacker can exhaust the firewall's connection state table "
                    "with a relatively low-bandwidth attack, taking the device or downstream hosts offline."
                ),
                recommendation=(
                    f"Enable flood protection for {', '.join(disabled_floods)} and set ApplyFlag to on. "
                    "Tune thresholds to match legitimate peak traffic — start with vendor defaults and "
                    "adjust based on traffic baselines. "
                    "Disabled flood protection directly enables MITRE ATT&CK T1498 (Network Denial of Service) "
                    "and T1499 (Endpoint DoS). "
                    "Aligns with OWASP A05:2021 – Security Misconfiguration and "
                    "NIST SP 800-53 Rev 5 SC-5 (Denial-of-Service Protection)."
                ),
                references=[
                    "MITRE ATT&CK T1498 – Network Denial of Service",
                    "MITRE ATT&CK T1499 – Endpoint Denial of Service",
                    "OWASP A05:2021 – Security Misconfiguration",
                    "NIST SP 800-53 Rev 5 SC-5 – Denial-of-Service Protection",
                    "CIS Controls v8 – 13.4 Perform Traffic Filtering Between Network Segments",
                ],
                location=(
                    "Firewall → Flood protection\n"
                    f"→ {' / '.join(disabled_floods)} flood → Enable → set ApplyFlag = On → Apply"
                ),
                affected=disabled_floods,
            ))

    return findings

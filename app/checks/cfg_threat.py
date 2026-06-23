"""Config checks — Threat protection (IPS, AV, Sandstorm, Web filter, App control, SSL inspection)."""
from .models import Finding, Severity
from .utils import v as _v, off as _off

_S = "Config — Threat Protection"


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
            exploitability="Low", impact_scope="Network", exposure="External",
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
                exploitability="High", impact_scope="Network", exposure="External",
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
                exploitability="Medium", impact_scope="Network", exposure="External",
            ))

    # ── Advanced Threat Protection (ATP / Sophos X-Ops threat feeds) ─────────
    atp_el = None
    for key in ("ThreatProtection", "ActiveThreatResponse", "ATP", "XOpsThreats",
                "AdvancedThreatProtection", "ThreatFeed"):
        atp_el = cfg.raw_sections.get(key) and cfg.system_settings.get(key)
        if not atp_el:
            # also check av_settings and sandbox_settings where some firmware stores ATP
            atp_el = cfg.av_settings.get(key) or cfg.sandbox_settings.get(key)
        if atp_el:
            break
    # Fallback: look for ATP keys embedded in any top-level settings dict
    _atp_state = ""
    _atp_policy = ""
    for d in (cfg.system_settings, cfg.av_settings, cfg.sandbox_settings, cfg.dos_settings):
        if not isinstance(d, dict):
            continue
        _atp_state  = _atp_state  or _v(d, "ThreatProtection", "ATPStatus", "ActiveThreatResponse",
                                         "XOpsThreatFeeds", "AdvancedThreatProtection")
        _atp_policy = _atp_policy or _v(d, "ATPPolicy", "ThreatPolicy", "ThreatAction",
                                         "DefaultAction", "DropAction")

    if not _atp_state:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="Advanced Threat Protection (ATP) state not detected",
            detail=(
                "No Advanced Threat Protection / Sophos X-Ops threat feed configuration was found. "
                "ATP blocks known malicious IPs, domains, and C2 infrastructure in real time using "
                "Sophos threat intelligence. Without it, connections to known-bad destinations succeed silently."
            ),
            recommendation=(
                "Enable ATP under Protect → Active threat response → Sophos X-Ops threat feeds "
                "and set the policy to 'Log and Drop'. "
                "Disabled ATP allows MITRE ATT&CK T1071 (Application Layer Protocol) C2 traffic "
                "and T1568 (Dynamic Resolution) to reach known-bad infrastructure without detection. "
                "Aligns with CIS Control 13.3 – Deploy a Network Intrusion Detection Solution."
            ),
            references=[
                "MITRE ATT&CK T1071 – Application Layer Protocol",
                "MITRE ATT&CK T1568 – Dynamic Resolution",
                "CIS Control 13.3 – Deploy a Network Intrusion Detection Solution",
                "OWASP A05:2021 – Security Misconfiguration",
            ],
            location=(
                "Protect → Active threat response → Sophos X-Ops threat feeds\n"
                "→ Enable → Policy: Log and Drop → Apply"
            ),
            exploitability="Medium", impact_scope="Network", exposure="External",
        ))
    else:
        if _off(_atp_state):
            findings.append(Finding(
                severity=Severity.HIGH,
                category=_S,
                title="Advanced Threat Protection (ATP) is disabled",
                detail=(
                    "ATP / Sophos X-Ops threat feeds are explicitly disabled. "
                    "Known C2 IPs, malware distribution points, and malicious domains are not blocked."
                ),
                recommendation=(
                    "Enable ATP and set policy to 'Log and Drop'. "
                    "Without ATP, MITRE ATT&CK T1071 (C2 over application protocols) and "
                    "T1071.001 (Web Protocols) to known-bad infrastructure succeed undetected. "
                    "Aligns with CIS Control 13.3."
                ),
                references=[
                    "MITRE ATT&CK T1071 – Application Layer Protocol",
                    "MITRE ATT&CK T1071.001 – Web Protocols",
                    "CIS Control 13.3 – Deploy a Network Intrusion Detection Solution",
                ],
                location=(
                    "Protect → Active threat response → Sophos X-Ops threat feeds\n"
                    "→ Enable → Policy: Log and Drop → Apply"
                ),
                exploitability="High", impact_scope="Network", exposure="External",
            ))
        elif _atp_policy and _atp_policy.lower() not in ("log and drop", "logdrop", "drop", "block"):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=_S,
                title="ATP policy is not set to 'Log and Drop'",
                detail=(
                    f"ATP is enabled but the action is '{_atp_policy}'. "
                    "'Log only' lets threats reach their destination — it generates alerts but does not block."
                ),
                recommendation=(
                    "Change the ATP policy to 'Log and Drop' so known-malicious connections are blocked, "
                    "not just logged. Log-only ATP gives attackers uninterrupted C2 access while generating "
                    "alerts that may go unreviewed. "
                    "Aligns with MITRE ATT&CK Mitigation M1031 – Network Intrusion Prevention."
                ),
                references=[
                    "MITRE ATT&CK Mitigation M1031 – Network Intrusion Prevention",
                    "MITRE ATT&CK T1071 – Application Layer Protocol",
                ],
                location=(
                    "Protect → Active threat response → Sophos X-Ops threat feeds\n"
                    "→ Policy → change to 'Log and Drop' → Apply"
                ),
                exploitability="Medium", impact_scope="Network", exposure="External",
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
            exploitability="Medium", impact_scope="Network", exposure="External",
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
                exploitability="High", impact_scope="Network", exposure="External",
            ))
        engine = _v(av, "AntiVirusEngine", "Engine", "AVEngine", "PrimaryEngine", "MalwareEngine")
        if engine and engine.lower() not in ("sophos", "sav", "savxl", "sophos av"):
            findings.append(Finding(
                severity=Severity.LOW,
                category=_S,
                title=f"Malware engine is not Sophos (detected: {engine})",
                detail=(
                    f"The configured antivirus engine is '{engine}'. "
                    "Sophos recommends the Sophos engine for best integration with threat intelligence, "
                    "Sandstorm cloud sandbox, and Live Protection. A non-Sophos engine may miss "
                    "threats detected by SophosLabs and will not benefit from ATP feed correlation."
                ),
                recommendation=(
                    "Set the primary antivirus engine to 'Sophos' under Configure → System services → "
                    "Malware Protection. This ensures the tightest integration with Sophos Live Protection "
                    "and Sandstorm analysis. "
                    "Aligns with CIS Control 10.1 – Deploy and Maintain Anti-Malware Software."
                ),
                references=[
                    "CIS Control 10.1 – Deploy and Maintain Anti-Malware Software",
                    "MITRE ATT&CK T1204.002 – User Execution: Malicious File",
                ],
                location=(
                    "Configure → System services → Malware Protection\n"
                    "→ Antivirus engine → set to Sophos → Apply"
                ),
                exploitability="Low", impact_scope="Network", exposure="External",
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
                exploitability="Low", impact_scope="Local", exposure="Internal",
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
            exploitability="Low", impact_scope="Network", exposure="External",
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
                exploitability="Low", impact_scope="Network", exposure="External",
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
            exploitability="Medium", impact_scope="Network", exposure="External",
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
                exploitability="Medium", impact_scope="Network", exposure="External",
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
            exploitability="Low", impact_scope="Network", exposure="External",
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
            exploitability="High", impact_scope="Network", exposure="External",
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
                exploitability="High", impact_scope="Network", exposure="External",
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
            exploitability="High", impact_scope="Network", exposure="External",
        ))
    else:
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
            flat_flag = dos.get(f"{key}ApplyFlag") or dos.get(f"{key}Enable") or ""
            if flat_flag and _off(str(flat_flag)) and proto not in disabled_floods:
                disabled_floods.append(proto)

        top_flag = _v(dos, "Enable", "Status", "Enabled", "FloodProtection")
        if _off(top_flag) and not disabled_floods:
            disabled_floods = ["SYN", "UDP", "ICMP", "IP"]

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
                exploitability="High", impact_scope="Network", exposure="External",
            ))

    # ── CIS 4.2 – Zero-day protection per outbound firewall rule ────────────
    _INT_SRC = {"lan", "internal", "corp", "users", "office", "employees", "staff"}
    _WAN_DST = {"wan", "internet", "untrust", "external", "outside", "public"}
    outbound_no_zdp = [
        r.get("name", f"Rule #{r.get('policy_index','?')}")
        for r in cfg.firewall_rules
        if r.get("action", "").lower() in ("accept", "allow")
        and not r.get("status", "enable").lower() in ("disable", "disabled")
        and any(z.strip().lower() in _INT_SRC or any(w in z.lower() for w in ("lan", "internal"))
                for z in r.get("src_zones", []))
        and any(z.strip().lower() in _WAN_DST or "wan" in z.lower()
                for z in r.get("dst_zones", []))
        and not r.get("zero_day", "").strip()
    ]
    if outbound_no_zdp:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="CIS 4.2 – Outbound rules missing Zero-day protection (Sandstorm)",
            detail=(
                "Outbound allow rules from internal zones to WAN do not have "
                "'Use Zero-day protection' enabled. Files downloaded via HTTP/HTTPS/FTP "
                "will not be submitted to cloud sandboxing for unknown threat analysis."
            ),
            recommendation=(
                "Edit each affected rule → Security features → Web filtering → "
                "enable 'Use Zero-day protection'. Also navigate to "
                "Monitor & Analyze → Zero-day protection → Protection Settings and "
                "remove any file type exceptions. "
                "Aligns with CIS Sophos Benchmark §4.2."
            ),
            references=[
                "CIS Sophos Benchmark §4.2",
                "CIS Control 10.1 – Deploy and Maintain Anti-Malware Software",
                "MITRE ATT&CK T1027 – Obfuscated Files or Information",
            ],
            location=(
                "Firewall → Rules and policies → Firewall rules\n"
                "→ Edit outbound rule → Security features → enable 'Use Zero-day protection' → Save"
            ),
            affected=outbound_no_zdp[:20],
            exploitability="Medium", impact_scope="Network", exposure="External",
        ))

    # ── CIS 4.4 – Synchronized Security Heartbeat per LAN/DMZ rule ──────────
    lan_rules_no_hb = [
        r.get("name", f"Rule #{r.get('policy_index','?')}")
        for r in cfg.firewall_rules
        if r.get("action", "").lower() in ("accept", "allow")
        and not r.get("status", "enable").lower() in ("disable", "disabled")
        and any(z.strip().lower() in _INT_SRC or any(w in z.lower() for w in ("lan", "internal"))
                for z in r.get("src_zones", []))
        and not r.get("heartbeat", "").strip()
    ]
    if lan_rules_no_hb:
        findings.append(Finding(
            severity=Severity.LOW,
            category=_S,
            title="CIS 4.4 – LAN/DMZ rules missing Synchronized Security Heartbeat",
            detail=(
                "Internal network rules do not enforce Synchronized Security Heartbeat. "
                "Without heartbeat enforcement, compromised endpoints with red/yellow health "
                "status can still access network resources freely."
            ),
            recommendation=(
                "Register Sophos Firewall with Sophos Central and enable Security Heartbeat. "
                "Edit LAN/DMZ firewall rules → Configure Synchronized Security Heartbeat → "
                "set 'Minimum source HB permitted' to Green or Yellow. "
                "Aligns with CIS Sophos Benchmark §4.4."
            ),
            references=[
                "CIS Sophos Benchmark §4.4",
                "CIS Control 10.6 – Centrally Manage Anti-Malware Software",
                "MITRE ATT&CK TA0008 – Lateral Movement",
            ],
            location=(
                "Firewall → Rules and policies → Firewall rules\n"
                "→ Edit rule → Configure Synchronized Security Heartbeat → "
                "set Minimum source HB permitted to Green → Save"
            ),
            affected=lan_rules_no_hb[:20],
            exploitability="Low", impact_scope="Network", exposure="Internal",
        ))

    # ── CIS 4.5 – MDR Threat Feeds ──────────────────────────────────────────
    atr = cfg.active_threat_response
    mdr_state = ""
    ndr_state = ""
    third_party_feeds = []
    if atr:
        mdr_state = _v(atr, "MDRThreatFeeds", "MDR", "MDREnabled", "Status")
        ndr_state = _v(atr, "NDREssentials", "NDR", "NDREnabled", "NDRStatus")
        third_party_feeds = atr.get("ThirdPartyFeeds", atr.get("ExternalFeeds", []))
    else:
        # Check system_settings for ATR-related keys
        for d in (cfg.system_settings, cfg.av_settings):
            if isinstance(d, dict):
                mdr_state = mdr_state or _v(d, "MDRThreatFeeds", "MDR", "MDREnabled")
                ndr_state = ndr_state or _v(d, "NDREssentials", "NDR", "NDREnabled")

    if not mdr_state or _off(mdr_state):
        findings.append(Finding(
            severity=Severity.LOW,
            category=_S,
            title="CIS 4.5 – MDR Threat Feeds not enabled",
            detail=(
                "MDR (Managed Detection and Response) Threat Feeds are not enabled. "
                "MDR analysts can push real-time threat intelligence to the firewall from "
                "Sophos Central to block known-malicious infrastructure immediately."
            ),
            recommendation=(
                "Navigate to Protect → Active threat response → MDR threat feeds → "
                "Enable and set action to 'Log and drop'. "
                "Requires Sophos MDR subscription and Sophos Central registration. "
                "Aligns with CIS Sophos Benchmark §4.5."
            ),
            references=[
                "CIS Sophos Benchmark §4.5",
                "CIS Control 8.2 – Collect Audit Logs",
                "MITRE ATT&CK T1071 – Application Layer Protocol",
            ],
            location=(
                "Protect → Active threat response → MDR threat feeds\n"
                "→ Enable → Action: Log and drop → Apply"
            ),
            exploitability="Low", impact_scope="Network", exposure="External",
        ))

    # ── CIS 4.7 – NDR Essentials ─────────────────────────────────────────────
    if not ndr_state or _off(ndr_state):
        findings.append(Finding(
            severity=Severity.LOW,
            category=_S,
            title="CIS 4.7 – NDR Essentials not enabled",
            detail=(
                "NDR (Network Detection and Response) Essentials is not configured. "
                "NDR uses machine learning to detect anomalous traffic patterns that may "
                "indicate active adversaries — threats that signature-based detection misses."
            ),
            recommendation=(
                "Navigate to Protect → Active threat response → NDR Essentials → "
                "Turn ON and select monitored interfaces. Set Minimum threat score to High risk. "
                "Aligns with CIS Sophos Benchmark §4.7."
            ),
            references=[
                "CIS Sophos Benchmark §4.7",
                "CIS Control 13.3 – Deploy a Network Intrusion Detection Solution",
                "MITRE ATT&CK TA0011 – Command and Control",
            ],
            location=(
                "Protect → Active threat response → NDR Essentials\n"
                "→ Turn ON → select interfaces → Minimum threat score: High risk → Apply"
            ),
            exploitability="Low", impact_scope="Network", exposure="External",
        ))

    # ── CIS 4.6 – Third-party Threat Feeds ──────────────────────────────────
    if not third_party_feeds:
        findings.append(Finding(
            severity=Severity.LOW,
            category=_S,
            title="CIS 4.6 – Third-party threat feeds not configured",
            detail=(
                "No third-party threat feed integrations were detected in the Active Threat "
                "Response configuration. Third-party feeds (e.g., FS-ISAC, commercial TI platforms) "
                "augment Sophos native intelligence with sector-specific or custom IOCs that "
                "SophosLabs may not yet include."
            ),
            recommendation=(
                "Navigate to Protect → Active threat response → Third-party threat feeds → "
                "Add feed URL(s) from a trusted threat intelligence provider. "
                "Set the action to 'Log and drop'. "
                "Aligns with CIS Sophos Benchmark §4.6."
            ),
            references=[
                "CIS Sophos Benchmark §4.6",
                "CIS Control 8.2 – Collect Audit Logs",
                "CIS Control 8.5 – Collect Detailed Audit Logs",
                "MITRE ATT&CK T1071 – Application Layer Protocol",
            ],
            location=(
                "Protect → Active threat response → Third-party threat feeds\n"
                "→ Add feed → URL → Action: Log and drop → Apply"
            ),
            exploitability="Low", impact_scope="Network", exposure="External",
        ))

    return findings

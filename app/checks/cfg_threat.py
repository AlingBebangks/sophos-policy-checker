"""Config checks — Threat protection (IPS, AV, Sandstorm, Web filter, App control, SSL inspection)."""
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
            recommendation="Create and apply IPS policies to all firewall rules handling untrusted traffic.",
            location="Intrusion prevention → IPS policies → Create policy → Apply to firewall rules",
        ))
    else:
        # Check rules that have no IPS assigned
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
                recommendation="Attach an IPS policy to every accept rule that handles WAN-originated traffic.",
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
                recommendation="Review and assign appropriate IPS policies.",
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
            recommendation="Enable malware scanning on HTTP, HTTPS, FTP, SMTP, and POP3 proxies.",
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
                recommendation="Enable AV scanning for all applicable protocols (HTTP, HTTPS, FTP, SMTP, POP3).",
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
            recommendation="Enable Sophos Sandstorm for HTTP/HTTPS and email if licensed.",
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
                recommendation="Enable Sandstorm cloud sandboxing if licensed.",
                location="Web → Malware protection → Sandstorm → Enable → Apply",
            ))

    # ── Web Filtering ─────────────────────────────────────────────────────────
    if not cfg.web_filter:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="No web filter policies found",
            detail="Without web filtering, users can browse malicious, phishing, or policy-violating sites freely.",
            recommendation="Create web filter policies and apply them to relevant firewall rules.",
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
                recommendation="Assign a web filter policy to all outbound rules from internal zones.",
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
            recommendation="Create application filter policies to block high-risk application categories.",
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
            recommendation="Configure SSL/TLS inspection with a trusted internal CA certificate deployed to endpoints.",
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
                recommendation="Enable SSL/TLS inspection and deploy the inspection CA certificate to managed endpoints.",
                location="Web → SSL/TLS inspection → Enable → Apply",
            ))

    return findings

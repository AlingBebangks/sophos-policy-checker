"""NAT rule checks."""
from .models import Finding, Severity

_NAT_NAV = "Firewall → Rules and policies → NAT rules"

_RISKY_PORTS = {
    "21": "FTP", "23": "Telnet", "135": "MS-RPC", "139": "NetBIOS",
    "445": "SMB", "1433": "MSSQL", "3306": "MySQL", "3389": "RDP",
    "5900": "VNC", "5432": "PostgreSQL", "27017": "MongoDB",
}


def _val(d: dict, *keys: str) -> str:
    for k in keys:
        v = d.get(k, "")
        if v:
            return str(v).strip()
    return ""


def run(cfg) -> list[Finding]:
    findings: list[Finding] = []
    rules = cfg.nat_rules

    risky_port_rules: list[tuple[str, str, str]] = []
    rdp_exposed: list[str] = []
    dnat_any_source: list[str] = []

    for rule in rules:
        name = _val(rule, "Name", "RuleName")
        translated_port = _val(rule, "TranslatedPort", "DestinationPort", "MappedPort")
        original_port = _val(rule, "OriginalPort", "ExternalPort")
        translated_dst = _val(rule, "TranslatedDestination", "MappedDestination", "TranslatedIP",
                              "InternalIP", "MappedHost")
        orig_src = _val(rule, "OriginalSource", "SourceNetwork", "OriginalSourceNetwork",
                        "SourceIP", "Source")
        rule_type = _val(rule, "Type", "RuleType", "NATType").lower()

        # Flag DNAT rules (identified by having a TranslatedDestination or explicit DNAT type)
        # where the original source is unrestricted — any internet host can reach the target.
        is_dnat = bool(translated_dst) or rule_type in ("dnat", "port forwarding", "portforwarding",
                                                         "server access assistant", "dst nat")
        if is_dnat and (not orig_src or orig_src.lower() in ("any", "all", "*")):
            dnat_any_source.append(name or "(unnamed)")

        for port, service in _RISKY_PORTS.items():
            if translated_port == port or original_port == port:
                risky_port_rules.append((name or "(unnamed)", port, service))
                if service == "RDP":
                    rdp_exposed.append(name or "(unnamed)")

    if rdp_exposed:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category="NAT Rules",
            title="RDP (port 3389) exposed via DNAT",
            detail=(
                "Remote Desktop Protocol is being port-forwarded from the WAN. "
                "Internet-exposed RDP is one of the most common ransomware entry points "
                "(BlueKeep CVE-2019-0708, DejaBlue CVE-2019-1181/1182)."
            ),
            recommendation=(
                "Remove direct RDP exposure immediately. Require RDP access only through a VPN tunnel. "
                "If direct access is essential, restrict source IPs, enable Network Level Authentication (NLA), "
                "and enforce MFA. "
                "Exposed RDP directly enables MITRE ATT&CK T1021.001 (Remote Desktop Protocol) "
                "and T1133 (External Remote Services), the top ransomware initial access vector. "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            references=[
                "MITRE ATT&CK T1021.001 – Remote Services: Remote Desktop Protocol",
                "MITRE ATT&CK T1133 – External Remote Services",
                "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                "OWASP A05:2021 – Security Misconfiguration",
                "CISA Alert AA20-073A – Enterprise VPN Security",
                "MS-ISAC Advisory – Ransomware Entry via Exposed RDP",
                "CVE-2019-0708 (BlueKeep) – Unauthenticated RCE via RDP",
            ],
            affected=rdp_exposed,
            location=(
                f"{_NAT_NAV}\n"
                "→ Find the rule forwarding port 3389 → click the three-dot menu → Delete or Edit "
                "to restrict the 'Original source' to a specific management IP only"
            ),
        ))

    other_risky = [(n, p, s) for n, p, s in risky_port_rules if s != "RDP"]
    if other_risky:
        affected = [f"{n} (port {p}/{s})" for n, p, s in other_risky]
        findings.append(Finding(
            severity=Severity.HIGH,
            category="NAT Rules",
            title="Sensitive services exposed via DNAT",
            detail=(
                "Port-forwarding rules expose services that should not be internet-accessible: "
                + ", ".join({s for _, _, s in other_risky}) + "."
            ),
            recommendation=(
                "Remove or restrict DNAT rules for database ports, SMB, RPC, FTP, and other "
                "internal-only protocols. Use VPN instead of direct port forwarding. "
                "Exposed internal services enable MITRE ATT&CK T1190 (Exploit Public-Facing Application) "
                "and T1021.002 (SMB/Windows Admin Shares for lateral movement). "
                "Database exposure enables T1078 (Valid Accounts) via credential brute-force. "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            references=[
                "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                "MITRE ATT&CK T1021.002 – Remote Services: SMB/Windows Admin Shares",
                "MITRE ATT&CK T1078 – Valid Accounts",
                "MITRE ATT&CK T1040 – Network Sniffing (FTP/Telnet)",
                "OWASP A05:2021 – Security Misconfiguration",
                "CIS Control 4.4 – Implement and Manage a Firewall on Servers",
            ],
            location=(
                f"{_NAT_NAV}\n"
                "→ Find the rule by name → click the three-dot menu → Delete, "
                "or Edit to add an 'Original source' restriction to a trusted IP range"
            ),
            affected=affected,
        ))

    if dnat_any_source:
        findings.append(Finding(
            severity=Severity.HIGH,
            category="NAT Rules",
            title="DNAT rules with unrestricted source (Any internet host allowed)",
            detail=(
                "These destination NAT rules forward inbound traffic to internal hosts without "
                "restricting the original source network. Any IP address on the internet can "
                "initiate a connection that will be forwarded to the internal target, regardless "
                "of the destination port."
            ),
            recommendation=(
                "Restrict the 'Original source' field on every DNAT rule to the specific IP "
                "addresses or CIDR ranges that legitimately need access. "
                "If the service must be publicly accessible (e.g. a web server), ensure it is "
                "placed in a DMZ and protected by IPS and application-layer filtering. "
                "Unrestricted DNAT enables MITRE ATT&CK T1190 (Exploit Public-Facing Application) "
                "and T1133 (External Remote Services) — the internal target is exposed to all "
                "internet scanning and exploit attempts. "
                "Aligns with OWASP A05:2021 – Security Misconfiguration and "
                "NIST SP 800-41 Rev 1 §3.3 – NAT Policy Least Privilege."
            ),
            location=(
                f"{_NAT_NAV}\n"
                "→ Click the rule name → Edit → under 'Original source', remove 'Any' "
                "and add specific allowed IP objects → Save"
            ),
            references=[
                "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                "MITRE ATT&CK T1133 – External Remote Services",
                "OWASP A05:2021 – Security Misconfiguration",
                "NIST SP 800-41 Rev 1 §3.3 – NAT Considerations",
                "CIS Controls v8 – 4.4 Implement and Manage a Firewall on Servers",
            ],
            affected=dnat_any_source,
        ))

    if not rules:
        findings.append(Finding(
            severity=Severity.INFO,
            category="NAT Rules",
            title="No NAT rules found",
            detail="No NATRule elements were detected.",
            recommendation="No action required if NAT is not in use.",
        ))

    return findings

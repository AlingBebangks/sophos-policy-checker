"""NAT rule checks."""
from .models import Finding, Severity

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

    for rule in rules:
        name = _val(rule, "Name", "RuleName")
        translated_port = _val(rule, "TranslatedPort", "DestinationPort", "MappedPort")
        original_port = _val(rule, "OriginalPort", "ExternalPort")
        rule_type = _val(rule, "RuleType", "Type")

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
                "Internet-exposed RDP is one of the most common ransomware entry points."
            ),
            recommendation=(
                "Remove direct RDP exposure. Require RDP access only through a VPN tunnel. "
                "If direct access is essential, restrict source IPs and enable NLA."
            ),
            references=["CISA Alert AA20-073A"],
            affected=rdp_exposed,
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
                "Remove or restrict DNAT rules for database ports, SMB, RPC, and other "
                "internal-only protocols. Use VPN instead of direct port forwarding."
            ),
            affected=affected,
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

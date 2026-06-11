"""Firewall rule policy checks."""
from .models import Finding, Severity

_ANY = {"any", "all", "*", ""}
_RISKY_SERVICES = {
    "telnet", "ftp", "tftp", "rsh", "rlogin", "snmp", "snmpv1", "snmpv2",
    "finger", "chargen", "echo", "discard", "rpc", "nfs",
}


def _is_any(values: list[str]) -> bool:
    return not values or any(v.strip().lower() in _ANY for v in values)


def run(cfg) -> list[Finding]:
    findings: list[Finding] = []
    rules = cfg.firewall_rules

    if not rules:
        findings.append(Finding(
            severity=Severity.INFO,
            category="Firewall Rules",
            title="No firewall rules found in config",
            detail="The parser found no FirewallRule elements. The config may use a different schema version.",
            recommendation="Verify the XML backup is a full Sophos XG/SFOS configuration export.",
        ))
        return findings

    any_any_rules: list[str] = []
    no_log_rules: list[str] = []
    disabled_rules: list[str] = []
    all_services_rules: list[str] = []
    risky_service_rules: list[tuple[str, str]] = []
    accept_no_dst_zone_rules: list[str] = []

    for rule in rules:
        name = rule.get("name") or "(unnamed)"
        status = rule.get("status", "Enable").lower()
        action = rule.get("action", "").lower()
        src_nets = rule.get("src_networks", [])
        dst_nets = rule.get("dst_networks", [])
        services = rule.get("services", [])
        log = rule.get("log_traffic", "Disable").lower()
        dst_zones = rule.get("dst_zones", [])

        if status in ("disable", "disabled", "0", "false"):
            disabled_rules.append(name)

        if action in ("accept", "allow") and _is_any(src_nets) and _is_any(dst_nets):
            any_any_rules.append(name)

        if log in ("disable", "disabled", "0", "false", "off") and action in ("accept", "allow"):
            no_log_rules.append(name)

        if _is_any(services) and action in ("accept", "allow"):
            all_services_rules.append(name)

        for svc in services:
            if svc.strip().lower() in _RISKY_SERVICES:
                risky_service_rules.append((name, svc))

        if action in ("accept", "allow") and _is_any(dst_zones):
            accept_no_dst_zone_rules.append(name)

    if any_any_rules:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category="Firewall Rules",
            title="Any-to-Any accept rules detected",
            detail=(
                "Rules that accept traffic from any source to any destination bypass all "
                "network segmentation and expose all hosts to each other."
            ),
            recommendation=(
                "Replace any-to-any rules with least-privilege rules specifying explicit "
                "source networks, destination networks, and required services only."
            ),
            references=["CIS Benchmark: Firewall Rule Review", "NIST SP 800-41 Rev 1 §3.2"],
            affected=any_any_rules,
        ))

    if all_services_rules:
        findings.append(Finding(
            severity=Severity.HIGH,
            category="Firewall Rules",
            title="Rules permitting all services",
            detail=(
                "Accept rules with no service restriction allow all TCP/UDP ports, "
                "greatly expanding the attack surface."
            ),
            recommendation=(
                "Restrict each rule to the minimum set of services required. "
                "Avoid using 'Any' in the service field for accept rules."
            ),
            affected=all_services_rules,
        ))

    if risky_service_rules:
        affected = [f"{r} ({s})" for r, s in risky_service_rules]
        findings.append(Finding(
            severity=Severity.HIGH,
            category="Firewall Rules",
            title="Rules allowing insecure/legacy services",
            detail=(
                "Rules explicitly permit cleartext or legacy protocols including: "
                + ", ".join({s for _, s in risky_service_rules})
                + ". These protocols transmit credentials and data in cleartext."
            ),
            recommendation=(
                "Replace Telnet with SSH, FTP with SFTP/FTPS, SNMP v1/v2 with SNMPv3. "
                "Remove rules for TFTP, RPC, Chargen unless absolutely required."
            ),
            references=["OWASP: Use of Broken or Risky Cryptographic Algorithm"],
            affected=affected,
        ))

    if no_log_rules:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="Firewall Rules",
            title="Accept rules with logging disabled",
            detail=(
                "Traffic permitted by these rules is not logged, making forensic "
                "investigation and anomaly detection impossible."
            ),
            recommendation=(
                "Enable logging on all accept rules. Forward logs to a central SIEM "
                "or syslog server for retention and alerting."
            ),
            affected=no_log_rules,
        ))

    if disabled_rules:
        findings.append(Finding(
            severity=Severity.LOW,
            category="Firewall Rules",
            title="Disabled firewall rules still present in policy",
            detail=(
                "Disabled rules accumulate over time and create policy clutter. "
                "They may be re-enabled accidentally during maintenance."
            ),
            recommendation=(
                "Review all disabled rules. Remove rules that are no longer needed. "
                "Document the reason any rule is intentionally disabled."
            ),
            affected=disabled_rules,
        ))

    return findings

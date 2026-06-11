"""Firewall rule policy checks."""
from .models import Finding, Severity

_ANY = {"any", "all", "*", ""}
_RISKY_SERVICES = {
    "telnet", "ftp", "tftp", "rsh", "rlogin", "snmp", "snmpv1", "snmpv2",
    "finger", "chargen", "echo", "discard", "rpc", "nfs",
}

_FW_NAV = "Firewall → Rules and policies → Firewall rules"


def _is_any(values: list[str]) -> bool:
    return not values or any(v.strip().lower() in _ANY for v in values)


def _label(rule: dict) -> str:
    name = rule.get("name") or "(unnamed)"
    pos = rule.get("position") or rule.get("policy_index", "")
    return f"{name} (policy position #{pos})"


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

    any_any_rules: list[dict] = []
    no_log_rules: list[dict] = []
    disabled_rules: list[dict] = []
    all_services_rules: list[dict] = []
    risky_service_rules: list[tuple[dict, str]] = []

    for rule in rules:
        status = rule.get("status", "Enable").lower()
        action = rule.get("action", "").lower()
        src_nets = rule.get("src_networks", [])
        dst_nets = rule.get("dst_networks", [])
        services = rule.get("services", [])
        log = rule.get("log_traffic", "Disable").lower()

        if status in ("disable", "disabled", "0", "false"):
            disabled_rules.append(rule)

        if action in ("accept", "allow") and _is_any(src_nets) and _is_any(dst_nets):
            any_any_rules.append(rule)

        if log in ("disable", "disabled", "0", "false", "off") and action in ("accept", "allow"):
            no_log_rules.append(rule)

        if _is_any(services) and action in ("accept", "allow"):
            all_services_rules.append(rule)

        for svc in services:
            if svc.strip().lower() in _RISKY_SERVICES:
                risky_service_rules.append((rule, svc))

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
            location=(
                f"{_FW_NAV}\n"
                "→ Click the rule name → Edit → change Source networks and Destination networks "
                "from 'Any' to specific host/network objects → Save"
            ),
            references=["CIS Benchmark: Firewall Rule Review", "NIST SP 800-41 Rev 1 §3.2"],
            affected=[_label(r) for r in any_any_rules],
            affected_rules=any_any_rules,
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
            location=(
                f"{_FW_NAV}\n"
                "→ Click the rule name → Edit → under 'Services / Destination', remove 'Any' "
                "and add only the specific services needed → Save"
            ),
            affected=[_label(r) for r in all_services_rules],
            affected_rules=all_services_rules,
        ))

    if risky_service_rules:
        # Annotate each rule dict with the flagged service for display
        annotated = []
        for r, svc in risky_service_rules:
            annotated.append({**r, "_flagged_service": svc})
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
            location=(
                f"{_FW_NAV}\n"
                "→ Click the rule name → Edit → under 'Services', remove the insecure service "
                "and replace with the secure equivalent → Save\n"
                "To delete the service object: Hosts and services → Services"
            ),
            references=["OWASP: Use of Broken or Risky Cryptographic Algorithm"],
            affected=[f"{_label(r)} — flagged service: {s}" for r, s in risky_service_rules],
            affected_rules=annotated,
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
            location=(
                f"{_FW_NAV}\n"
                "→ Click the rule name → Edit → scroll to 'Log traffic' → set to 'Enable' → Save"
            ),
            affected=[_label(r) for r in no_log_rules],
            affected_rules=no_log_rules,
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
            location=(
                f"{_FW_NAV}\n"
                "→ Find the rule (shown with a grey toggle) → click the three-dot menu "
                "on the right → Delete (if no longer needed) or add a description explaining why it is disabled"
            ),
            affected=[_label(r) for r in disabled_rules],
            affected_rules=disabled_rules,
        ))

    return findings

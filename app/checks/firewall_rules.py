"""Firewall rule policy checks."""
import re
from .models import Finding, Severity
from .utils import v as _v, off as _off

_ANY = {"any", "all", "*", ""}
_WAN_ZONES  = {"wan", "internet", "untrust", "external", "outside", "public"}
_DMZ_ZONES  = {"dmz", "servers", "server", "perimeter", "semi-trusted"}
_INT_ZONES  = {"lan", "internal", "inside", "trusted", "corp", "corporate",
               "users", "user", "employees", "staff", "office", "local"}
_RISKY_SERVICES = {
    "telnet", "ftp", "tftp", "rsh", "rlogin", "snmp", "snmpv1", "snmpv2",
    "finger", "chargen", "echo", "discard", "rpc", "nfs",
}
_NOT_NAMES = {
    "wan", "lan", "dmz", "vpn", "nat", "dns", "ntp", "ftp", "ssh", "ssl", "tls",
    "http", "https", "smtp", "snmp", "vlan", "mgmt", "mgmnt", "any", "all",
    "allow", "deny", "drop", "accept", "reject", "inbound", "outbound", "internet",
    "firewall", "policy", "rule", "zone", "network", "host", "server", "client",
    "internal", "external", "public", "private", "guest", "corp", "corporate",
    "voice", "data", "video", "iot", "prod", "dev", "test", "staging", "backup",
    "access", "block", "permit", "local", "remote", "static", "dynamic",
}
_PII_RE = re.compile(r'\b([A-Z][a-z]{1,})\s+([A-Z][a-z]{1,})\b')

_FW_NAV = "Firewall → Rules and policies → Firewall rules"


def _is_any(values: list[str]) -> bool:
    return not values or any(v.strip().lower() in _ANY for v in values)


def _zones_explicit(zones: list[str]) -> bool:
    """True when at least one zone is named and not a wildcard — zones are intentionally scoped."""
    return bool(zones) and not any(z.strip().lower() in _ANY for z in zones)


def _zone_tier(zones: list[str]) -> str:
    """Classify a zone list into WAN / DMZ / Internal / Unknown.

    Checks exact name first, then falls back to keyword-in-name matching so
    custom zone names like 'pcare servers' or 'HQ-LAN' are classified correctly.
    """
    names = {z.strip().lower() for z in zones}
    # Exact match
    if names & _WAN_ZONES:  return "WAN"
    if names & _DMZ_ZONES:  return "DMZ"
    if names & _INT_ZONES:  return "Internal"
    # Keyword-in-name fallback: "pcare servers" contains "server" → DMZ
    for n in names:
        words = set(re.split(r"[\s\-_/]+", n))
        if words & _WAN_ZONES:  return "WAN"
        if words & _DMZ_ZONES:  return "DMZ"
        if words & _INT_ZONES:  return "Internal"
    return "Unknown"


def _has_pii(text: str) -> bool:
    for m in _PII_RE.finditer(text or ""):
        w1, w2 = m.group(1).lower(), m.group(2).lower()
        if w1 not in _NOT_NAMES and w2 not in _NOT_NAMES:
            return True
    return False


def _label(rule: dict) -> str:
    name = rule.get("name") or rule.get("id") or ""
    pos  = rule.get("position") or rule.get("policy_index", "")
    label = name if name else f"Rule #{pos}"
    return f"{label} (policy position #{pos})" if name else f"Rule #{pos} (no name in config)"


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
            exploitability="Low", impact_scope="Local", exposure="Internal",
        ))
        return findings

    # Any-to-any rules split by zone combination (each has a different risk profile)
    # True any-to-any: BOTH zones AND networks are unspecified (or "Any")
    aa_wan_to_any:  list[dict] = []   # WAN → * : internet can reach everything — Critical
    aa_dmz_to_int:  list[dict] = []   # DMZ → Internal : compromised server pivots in — Critical
    aa_int_to_wan:  list[dict] = []   # Internal → WAN : unrestricted exfil path — High
    aa_int_to_dmz:  list[dict] = []   # Internal → DMZ : flat access to all servers — High
    aa_int_to_int:  list[dict] = []   # Internal → Internal : lateral movement — Medium
    aa_other:       list[dict] = []   # Unknown zones — Medium fallback
    # Zone-scoped broad network: zones ARE defined but src/dst networks are Any.
    # The zone pair constrains direction, but all hosts within each zone are reachable.
    broad_net_rules: list[dict] = []  # Medium — no host segmentation within zone pair
    wan_any_src_rules: list[dict] = []
    no_log_rules: list[dict] = []
    no_log_wan_rules: list[dict] = []   # subset: WAN-facing rules with no logging
    no_ips_rules: list[dict] = []       # WAN-facing accept rules with no IPS policy
    disabled_accept_rules: list[dict] = []
    disabled_drop_rules: list[dict] = []
    all_services_rules: list[dict] = []
    risky_service_rules: list[tuple[dict, str]] = []
    pii_rules: list[dict] = []
    shadowed_rules: list[tuple[dict, dict]] = []  # (shadowed_rule, shadowing_rule)
    duplicate_rules: list[tuple[dict, dict]] = []  # (later_rule, earlier_rule)
    _rule_fingerprints: dict = {}  # fingerprint -> first rule seen
    # Track per-rule logging so other findings can set detectability
    _logged_ids: set = set()
    _unlogged_ids: set = set()

    for rule in rules:
        status = rule.get("status", "Enable").lower()
        action = rule.get("action", "").lower()
        src_zones = rule.get("src_zones", [])
        dst_zones = rule.get("dst_zones", [])
        src_nets = rule.get("src_networks", [])
        dst_nets = rule.get("dst_networks", [])
        services = rule.get("services", [])
        log = rule.get("log_traffic", "").lower()
        rule_id = rule.get("id") or rule.get("policy_index")
        is_wan = any(z.strip().lower() in _WAN_ZONES for z in src_zones)

        # Track logging state for detectability scoring
        if log and log not in ("disable", "disabled", "0", "false", "off"):
            _logged_ids.add(rule_id)
        elif log and log in ("disable", "disabled", "0", "false", "off"):
            _unlogged_ids.add(rule_id)

        is_disabled = status in ("disable", "disabled", "0", "false")
        if is_disabled:
            if action in ("drop", "deny", "reject"):
                disabled_drop_rules.append(rule)
            else:
                disabled_accept_rules.append(rule)

        if (action in ("accept", "allow") and not is_disabled
                and is_wan and _is_any(src_nets)):
            wan_any_src_rules.append(rule)

        if _has_pii(rule.get("name", "") or "") or _has_pii(rule.get("description", "") or ""):
            pii_rules.append(rule)

        if action in ("accept", "allow") and _is_any(src_nets) and _is_any(dst_nets):
            src_tier = _zone_tier(src_zones)
            dst_tier = _zone_tier(dst_zones)
            src_explicit = _zones_explicit(src_zones)
            dst_explicit = _zones_explicit(dst_zones)

            if src_explicit and dst_explicit:
                # Both zones intentionally scoped — not any-to-any, just broad network objects.
                broad_net_rules.append(rule)
            elif src_explicit and not dst_explicit:
                # Source zone is named; destination is "any zone".
                # Risk is driven by what the source tier is — a DMZ server sending
                # to any zone is still a pivot risk; an internal host is lower.
                if src_tier == "WAN":
                    aa_wan_to_any.append(rule)
                elif src_tier == "DMZ":
                    aa_dmz_to_int.append(rule)   # DMZ → unconstrained = lateral pivot risk
                elif src_tier == "Internal":
                    aa_int_to_wan.append(rule)   # Internal → unconstrained = exfil risk
                else:
                    aa_other.append(rule)
            elif not src_explicit and dst_explicit:
                # Destination zone named; source is "any zone" — traffic from anywhere to a zone.
                if dst_tier == "Internal":
                    aa_wan_to_any.append(rule)   # unknown src → internal = inbound risk
                elif dst_tier == "DMZ":
                    aa_wan_to_any.append(rule)
                else:
                    aa_other.append(rule)
            else:
                # Neither zone is constrained — true any-to-any.
                if src_tier == "WAN":
                    aa_wan_to_any.append(rule)
                elif src_tier == "DMZ" and dst_tier == "Internal":
                    aa_dmz_to_int.append(rule)
                elif src_tier == "Internal" and dst_tier == "WAN":
                    aa_int_to_wan.append(rule)
                elif src_tier == "Internal" and dst_tier == "DMZ":
                    aa_int_to_dmz.append(rule)
                elif src_tier == "Internal" and dst_tier in ("Internal", "Unknown"):
                    aa_int_to_int.append(rule)
                else:
                    aa_other.append(rule)

        if log and log in ("disable", "disabled", "0", "false", "off") and action in ("accept", "allow"):
            no_log_rules.append(rule)
            if is_wan:
                no_log_wan_rules.append(rule)

        # IPS policy missing on WAN-facing or DMZ-sourced accept rules
        if (action in ("accept", "allow") and not is_disabled
                and (is_wan or _zone_tier(src_zones) == "DMZ")
                and not rule.get("ips_policy", "").strip()):
            no_ips_rules.append(rule)

        if _is_any(services) and action in ("accept", "allow"):
            all_services_rules.append(rule)

        for svc in services:
            if svc.strip().lower() in _RISKY_SERVICES:
                risky_service_rules.append((rule, svc))

        # Duplicate rule detection: same action + zones + networks + services
        fp = (
            action,
            tuple(sorted(z.lower() for z in src_zones)),
            tuple(sorted(z.lower() for z in dst_zones)),
            tuple(sorted(n.lower() for n in src_nets)),
            tuple(sorted(n.lower() for n in dst_nets)),
            tuple(sorted(s.lower() for s in services)),
        )
        if fp in _rule_fingerprints:
            duplicate_rules.append((rule, _rule_fingerprints[fp]))
        else:
            _rule_fingerprints[fp] = rule

    # ── Shadowed rule detection ───────────────────────────────────────────────
    # A rule is shadowed when a preceding rule already covers ALL its traffic:
    # broader action (accept/accept or deny/deny) + Any src + Any dst + Any svc
    # that encompasses the later rule's zones.
    _any_accept_seen: list[dict] = []  # any-src any-dst any-svc accept rules seen so far
    _any_deny_seen:   list[dict] = []  # same but for deny/drop

    def _zones_covered(broad: list, narrow: list) -> bool:
        """True if broad zone list covers narrow (Any covers everything)."""
        if not broad:       # broad is Any — covers all zones
            return True
        if not narrow:      # narrow is also Any — only covered if broad is also Any
            return not broad
        return set(z.lower() for z in narrow).issubset(z.lower() for z in broad)

    for rule in rules:
        action  = rule.get("action", "").lower()
        sz      = rule.get("src_zones", [])
        dz      = rule.get("dst_zones", [])
        sn      = rule.get("src_networks", [])
        dn      = rule.get("dst_networks", [])
        sv      = rule.get("services", [])
        is_acc  = action in ("accept", "allow")
        is_den  = action in ("drop", "deny", "reject")

        # Check if this rule is shadowed by any earlier any-to-any rule
        shadow_pool = _any_accept_seen if is_acc else (_any_deny_seen if is_den else [])
        for broad in shadow_pool:
            if (_zones_covered(broad.get("src_zones", []), sz)
                    and _zones_covered(broad.get("dst_zones", []), dz)):
                shadowed_rules.append((rule, broad))
                break

        # Track this rule if it is an any-to-any-any rule (potential shadower)
        if is_acc and _is_any(sn) and _is_any(dn) and _is_any(sv):
            _any_accept_seen.append(rule)
        elif is_den and _is_any(sn) and _is_any(dn) and _is_any(sv):
            _any_deny_seen.append(rule)

    def _detectability(rule_list: list[dict]) -> str:
        """Return detectability label based on logging state of the affected rules."""
        ids = {r.get("id") or r.get("policy_index") for r in rule_list}
        any_unlogged = bool(ids & _unlogged_ids)
        any_logged   = bool(ids & _logged_ids)
        if any_unlogged and not any_logged:
            return "Unlogged"
        if any_logged and not any_unlogged:
            return "Logged"
        if any_unlogged:
            return "Unlogged"  # mixed — penalise for the unlogged subset
        return "Unknown"

    _aa_nav = (
        f"{_FW_NAV}\n"
        "→ Click the rule name → Edit → replace 'Any' in Source/Destination networks "
        "with specific host or network objects → Save"
    )
    _aa_refs = [
        "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
        "MITRE ATT&CK TA0008 – Lateral Movement",
        "MITRE ATT&CK T1133 – External Remote Services",
        "OWASP A05:2021 – Security Misconfiguration",
        "CIS Control 4 – Secure Configuration of Enterprise Assets and Software",
        "NIST SP 800-41 Rev 1 §3.2 – Firewall Policy",
    ]

    if aa_wan_to_any:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category="Firewall Rules",
            title="Any-to-Any accept from WAN — internet can reach all internal hosts",
            detail=(
                "These rules accept traffic from the WAN zone to any destination with no network "
                "restriction. Any host on the internet can directly reach every internal host and "
                "service, completely collapsing the network perimeter. This is the highest-risk "
                "firewall misconfiguration possible."
            ),
            recommendation=(
                "Remove or immediately restrict these rules. Specify the exact destination host/network "
                "and service required. WAN-to-any rules enable MITRE ATT&CK T1190 (Exploit Public-Facing "
                "Application) and T1133 (External Remote Services) for every device on the network. "
                "No business case justifies unrestricted internet-to-internal access. "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            location=_aa_nav, references=_aa_refs,
            affected=[_label(r) for r in aa_wan_to_any],
            affected_rules=aa_wan_to_any,
            exploitability="High", impact_scope="Network", exposure="External",
            detectability=_detectability(aa_wan_to_any),
        ))

    if aa_dmz_to_int:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category="Firewall Rules",
            title="Any-to-Any accept from DMZ to Internal — pivot path from compromised server",
            detail=(
                "These rules allow unrestricted traffic from the DMZ to the internal network. "
                "If any DMZ host is compromised (e.g. a public-facing web server), the attacker "
                "gains an unrestricted pivot path directly into the internal LAN, bypassing the "
                "intended segmentation that DMZ architecture provides."
            ),
            recommendation=(
                "DMZ-to-Internal traffic must be explicitly denied by default. Only specific, "
                "necessary return flows (e.g. database callbacks) should be permitted, locked "
                "to exact source/destination IPs and ports. "
                "This directly blocks MITRE ATT&CK T1021 (Remote Services) and TA0008 (Lateral Movement) "
                "from a compromised DMZ host. Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            location=_aa_nav, references=_aa_refs,
            affected=[_label(r) for r in aa_dmz_to_int],
            affected_rules=aa_dmz_to_int,
            exploitability="High", impact_scope="Network", exposure="Adjacent",
            detectability=_detectability(aa_dmz_to_int),
        ))

    if aa_int_to_wan:
        findings.append(Finding(
            severity=Severity.HIGH,
            category="Firewall Rules",
            title="Any-to-Any accept from Internal to WAN — unrestricted outbound to internet",
            detail=(
                "These rules allow any internal host to send traffic to any internet destination "
                "on any port. This creates an unrestricted data exfiltration path and enables "
                "malware C2 callbacks on any port."
            ),
            recommendation=(
                "Restrict outbound WAN access to specific approved destination networks and services. "
                "Use URL filtering or web proxy to control outbound HTTP/HTTPS. "
                "Unrestricted outbound enables MITRE ATT&CK T1041 (Exfiltration Over C2 Channel), "
                "T1071 (Application Layer Protocol), and T1048 (Exfiltration Over Alternative Protocol). "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            location=_aa_nav,
            references=[
                "MITRE ATT&CK T1041 – Exfiltration Over C2 Channel",
                "MITRE ATT&CK T1071 – Application Layer Protocol",
                "MITRE ATT&CK T1048 – Exfiltration Over Alternative Protocol",
                "OWASP A05:2021 – Security Misconfiguration",
                "CIS Control 4 – Secure Configuration of Enterprise Assets and Software",
            ],
            affected=[_label(r) for r in aa_int_to_wan],
            affected_rules=aa_int_to_wan,
            exploitability="Medium", impact_scope="Network", exposure="External",
            detectability=_detectability(aa_int_to_wan),
        ))

    if aa_int_to_dmz:
        findings.append(Finding(
            severity=Severity.HIGH,
            category="Firewall Rules",
            title="Any-to-Any accept from Internal to DMZ — flat access to all DMZ servers",
            detail=(
                "Internal hosts can reach any DMZ server on any port without restriction. "
                "A compromised internal workstation can attack all DMZ services directly. "
                "This also violates the principle of least privilege for server access."
            ),
            recommendation=(
                "Restrict internal-to-DMZ access to specific source hosts and the minimum required "
                "ports (e.g. only the DB server on 1433 from the app server's IP). "
                "This limits MITRE ATT&CK T1021 (Remote Services) lateral movement from a "
                "compromised workstation to DMZ servers. Aligns with OWASP A05:2021."
            ),
            location=_aa_nav, references=_aa_refs,
            affected=[_label(r) for r in aa_int_to_dmz],
            affected_rules=aa_int_to_dmz,
            exploitability="Medium", impact_scope="Network", exposure="Adjacent",
            detectability=_detectability(aa_int_to_dmz),
        ))

    if aa_int_to_int:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="Firewall Rules",
            title="Any-to-Any accept within Internal network — no east-west segmentation",
            detail=(
                "Internal hosts can reach any other internal host on any port. "
                "Once an attacker compromises one workstation or server, they can freely move "
                "laterally across the entire internal network with no firewall obstruction."
            ),
            recommendation=(
                "Implement east-west (internal) segmentation using VLANs and firewall rules "
                "that restrict host-to-host communication to only what is operationally required. "
                "Flat internal networks directly enable MITRE ATT&CK TA0008 (Lateral Movement), "
                "T1021 (Remote Services), and T1570 (Lateral Tool Transfer). "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            location=_aa_nav,
            references=[
                "MITRE ATT&CK TA0008 – Lateral Movement",
                "MITRE ATT&CK T1021 – Remote Services",
                "MITRE ATT&CK T1570 – Lateral Tool Transfer",
                "OWASP A05:2021 – Security Misconfiguration",
                "CIS Control 12.2 – Establish and Maintain a Secure Network Architecture",
            ],
            affected=[_label(r) for r in aa_int_to_int],
            affected_rules=aa_int_to_int,
            exploitability="Medium", impact_scope="Network", exposure="Internal",
            detectability=_detectability(aa_int_to_int),
        ))

    if aa_other:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="Firewall Rules",
            title="Any-to-Any accept rules with unclassified zone combination",
            detail=(
                "These rules accept traffic from any source to any destination but their zone "
                "names did not match known WAN/DMZ/Internal patterns. The risk depends on what "
                "those zones represent — review manually."
            ),
            recommendation=(
                "Review each rule and restrict source networks, destination networks, and services "
                "to the minimum required. Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            location=_aa_nav, references=_aa_refs,
            affected=[_label(r) for r in aa_other],
            affected_rules=aa_other,
            exploitability="Medium", impact_scope="Network", exposure="Internal",
            detectability=_detectability(aa_other),
        ))

    if broad_net_rules:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="Firewall Rules",
            title="Accept rules with no host segmentation — all hosts within zone pair are reachable",
            detail=(
                "These rules specify source and destination zones explicitly (traffic direction is "
                "intentional), but the source and destination network objects are set to 'Any'. "
                "Every host within the source zone can reach every host within the destination zone. "
                "While the zone pair constrains the traffic direction, there is no host-level "
                "access control — a single compromised host in the source zone can freely contact "
                "any host in the destination zone without restriction."
            ),
            recommendation=(
                "Replace the 'Any' network objects with explicit host groups, subnets, or named "
                "network objects that represent only the legitimate communicating endpoints. "
                "Apply the principle of least privilege at the host/subnet level, not just the zone level. "
                "Aligns with CIS Control 12.2 – Establish and Maintain a Secure Network Architecture "
                "and NIST SP 800-41 §4.3 – Inbound/Outbound Traffic Filtering."
            ),
            references=[
                "CIS Control 12.2 – Establish and Maintain a Secure Network Architecture",
                "NIST SP 800-41 §4.3 – Filtering Inbound and Outbound Traffic",
                "OWASP A05:2021 – Security Misconfiguration",
            ],
            location=(
                f"{_FW_NAV}\n"
                "→ Edit each rule → Source networks / Destination networks "
                "→ Replace 'Any' with specific host/subnet objects → Save"
            ),
            affected=[_label(r) for r in broad_net_rules],
            affected_rules=broad_net_rules,
            exploitability="Medium", impact_scope="Network", exposure="Internal",
            detectability=_detectability(broad_net_rules),
        ))

    if wan_any_src_rules:
        findings.append(Finding(
            severity=Severity.HIGH,
            category="Firewall Rules",
            title="WAN-zone accept rules with unrestricted source network",
            detail=(
                "These rules accept traffic sourced from the WAN zone without restricting the "
                "source network to specific IP addresses. Any host on the internet can initiate "
                "a connection matching these rules."
            ),
            recommendation=(
                "Restrict the source network on every WAN-sourced accept rule to the specific "
                "IP addresses or CIDR ranges that legitimately need access. "
                "Unrestricted WAN accept rules directly enable MITRE ATT&CK T1190 "
                "(Exploit Public-Facing Application) and T1133 (External Remote Services) — "
                "any internet host can probe and attack the permitted destination. "
                "Aligns with OWASP A05:2021 – Security Misconfiguration and the principle of least privilege. "
                "If broad access is intentional (e.g. public web server), validate that IPS and AV policies "
                "are applied and that the destination is isolated in a DMZ."
            ),
            location=(
                f"{_FW_NAV}\n"
                "→ Click the rule name → Edit → under 'Source networks', remove 'Any' "
                "and add specific allowed host/network objects → Save"
            ),
            references=[
                "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                "MITRE ATT&CK T1133 – External Remote Services",
                "OWASP A05:2021 – Security Misconfiguration",
                "NIST SP 800-41 Rev 1 §3.2 – Least-Privilege Firewall Policy",
                "CIS Controls v8 – 4.4 Implement and Manage a Firewall on Servers",
            ],
            affected=[_label(r) for r in wan_any_src_rules],
            affected_rules=wan_any_src_rules,
            exploitability="High", impact_scope="Network", exposure="External",
            detectability=_detectability(wan_any_src_rules),
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
                "Avoid using 'Any' in the service field for accept rules. "
                "Broad service permissions support MITRE ATT&CK T1190 (Exploit Public-Facing Application) "
                "and T1046 (Network Service Discovery) by giving attackers unrestricted port access. "
                "Aligns with OWASP A05:2021 – Security Misconfiguration and the principle of least privilege."
            ),
            location=(
                f"{_FW_NAV}\n"
                "→ Click the rule name → Edit → under 'Services / Destination', remove 'Any' "
                "and add only the specific services needed → Save"
            ),
            references=[
                "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                "MITRE ATT&CK T1046 – Network Service Discovery",
                "OWASP A05:2021 – Security Misconfiguration",
                "CIS Control 4.4 – Implement and Manage a Firewall on Servers",
                "NIST SP 800-41 Rev 1 §3.1 – Least Privilege for Firewall Rules",
            ],
            affected=[_label(r) for r in all_services_rules],
            affected_rules=all_services_rules,
            exploitability="High", impact_scope="Network", exposure="External",
            detectability=_detectability(all_services_rules),
        ))

    if risky_service_rules:
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
                + ". These protocols transmit credentials and data in cleartext, enabling interception."
            ),
            recommendation=(
                "Replace Telnet with SSH, FTP with SFTP/FTPS, SNMP v1/v2c with SNMPv3 (auth+priv). "
                "Remove rules for TFTP, RPC, Chargen, and r-protocols unless strictly required. "
                "Cleartext protocols directly enable MITRE ATT&CK T1040 (Network Sniffing) and "
                "T1557 (Adversary-in-the-Middle), allowing credential harvest and session hijacking. "
                "Aligns with OWASP A02:2021 – Cryptographic Failures."
            ),
            location=(
                f"{_FW_NAV}\n"
                "→ Click the rule name → Edit → under 'Services', remove the insecure service "
                "and replace with the secure equivalent → Save\n"
                "To delete the service object: Hosts and services → Services"
            ),
            references=[
                "MITRE ATT&CK T1040 – Network Sniffing",
                "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                "MITRE ATT&CK T1110 – Brute Force (cleartext auth enables credential capture)",
                "OWASP A02:2021 – Cryptographic Failures",
                "OWASP Testing Guide v4.2 – WSTG-CRYP-03 (Weak Cryptography)",
                "NIST SP 800-52 Rev 2 – Guidelines for TLS Implementations",
            ],
            affected=[f"{_label(r)} — flagged service: {s}" for r, s in risky_service_rules],
            affected_rules=annotated,
            exploitability="Medium", impact_scope="Network", exposure="Adjacent",
            detectability=_detectability([r for r, _ in risky_service_rules]),
        ))

    if no_log_rules:
        # WAN-facing rules without logging are significantly more dangerous:
        # an attacker exploiting them leaves zero trace at the perimeter.
        has_wan = bool(no_log_wan_rules)
        sev     = Severity.HIGH if has_wan else Severity.MEDIUM
        exp     = "External" if has_wan else "Internal"
        detail_extra = (
            f" {len(no_log_wan_rules)} of these rule(s) are WAN-facing — "
            "perimeter traffic will be completely invisible to monitoring."
            if has_wan else ""
        )
        findings.append(Finding(
            severity=sev,
            category="Firewall Rules",
            title="Accept rules with logging disabled",
            detail=(
                "Traffic permitted by these rules is not logged, making forensic "
                f"investigation and anomaly detection impossible.{detail_extra}"
            ),
            recommendation=(
                "Enable logging on all accept rules. Forward logs to a central SIEM "
                "or syslog server for retention and alerting. "
                "Missing logs directly enable MITRE ATT&CK T1562.008 (Disable or Modify Cloud Logs) "
                "and T1070 (Indicator Removal) — attackers rely on log gaps for dwell time. "
                "Aligns with OWASP A09:2021 – Security Logging and Monitoring Failures."
            ),
            location=(
                f"{_FW_NAV}\n"
                "→ Click the rule name → Edit → scroll to 'Log traffic' → set to 'Enable' → Save"
            ),
            references=[
                "MITRE ATT&CK T1562.008 – Impair Defenses: Disable or Modify Cloud Logs",
                "MITRE ATT&CK T1070 – Indicator Removal",
                "OWASP A09:2021 – Security Logging and Monitoring Failures",
                "CIS Control 8 – Audit Log Management",
                "NIST SP 800-92 – Guide to Computer Security Log Management",
            ],
            affected=[_label(r) for r in no_log_rules],
            affected_rules=no_log_rules,
            exploitability="Medium" if has_wan else "Low",
            impact_scope="Network" if has_wan else "Local",
            exposure=exp,
            detectability="Unlogged",  # by definition — these rules have logging off
        ))

    if disabled_drop_rules:
        findings.append(Finding(
            severity=Severity.HIGH,
            category="Firewall Rules",
            title="Disabled DROP/DENY rules — safety net removed",
            detail=(
                "These rules are configured to DROP or DENY traffic but are currently disabled. "
                "A disabled deny rule is more dangerous than a disabled accept rule: the safety net "
                "that would block malicious traffic is silently absent. If traffic is not matched by "
                "an earlier accept rule, it may fall through to a permissive default or another allow rule, "
                "passing uninspected."
            ),
            recommendation=(
                "Re-enable all DROP/DENY rules unless there is a documented and reviewed reason to disable them. "
                "Disabled deny rules directly support MITRE ATT&CK T1562.004 "
                "(Impair Defenses: Disable or Modify System Firewall) — "
                "an attacker or misconfiguration that disables a block rule creates an uncontrolled traffic path. "
                "Aligns with OWASP A05:2021 – Security Misconfiguration. "
                "Review each rule: re-enable if needed, delete if obsolete, or document the business justification."
            ),
            location=(
                f"{_FW_NAV}\n"
                "→ Find the disabled rule (grey toggle) → click the toggle to re-enable → Save\n"
                "Or: three-dot menu → Delete if the rule is confirmed obsolete"
            ),
            references=[
                "MITRE ATT&CK T1562.004 – Impair Defenses: Disable or Modify System Firewall",
                "MITRE ATT&CK TA0008 – Lateral Movement (enabled by missing deny rules)",
                "OWASP A05:2021 – Security Misconfiguration",
                "NIST SP 800-41 Rev 1 §3.2 – Default-Deny Firewall Policy",
                "CIS Control 4.4 – Implement and Manage a Firewall on Servers",
            ],
            affected=[_label(r) for r in disabled_drop_rules],
            affected_rules=disabled_drop_rules,
            exploitability="Medium", impact_scope="Network", exposure="Internal",
            detectability=_detectability(disabled_drop_rules),
        ))

    if disabled_accept_rules:
        findings.append(Finding(
            severity=Severity.LOW,
            category="Firewall Rules",
            title="Disabled accept rules still present in policy",
            detail=(
                "Disabled accept rules accumulate over time and create policy clutter. "
                "They may be re-enabled accidentally during maintenance."
            ),
            recommendation=(
                "Review all disabled accept rules. Remove rules that are no longer needed. "
                "Document the reason any rule is intentionally disabled. "
                "Stale rules can be re-enabled to support MITRE ATT&CK T1562.004 "
                "(Impair Defenses: Disable or Modify System Firewall) during an incident."
            ),
            location=(
                f"{_FW_NAV}\n"
                "→ Find the rule (shown with a grey toggle) → click the three-dot menu "
                "on the right → Delete (if no longer needed) or add a description explaining why it is disabled"
            ),
            references=[
                "MITRE ATT&CK T1562.004 – Impair Defenses: Disable or Modify System Firewall",
                "OWASP A05:2021 – Security Misconfiguration",
                "CIS Control 4.1 – Establish and Maintain a Secure Configuration Process",
            ],
            affected=[_label(r) for r in disabled_accept_rules],
            affected_rules=disabled_accept_rules,
            exploitability="Low", impact_scope="Local", exposure="Internal",
            detectability=_detectability(disabled_accept_rules),
        ))

    if pii_rules:
        findings.append(Finding(
            severity=Severity.LOW,
            category="Firewall Rules",
            title="Possible personal names (PII) embedded in rule names or descriptions",
            detail=(
                "One or more firewall rules contain text that matches the pattern of a personal "
                "name (two consecutive title-cased words). Using names of individuals in firewall "
                "rule objects ties infrastructure policy to specific people, exposing personal data "
                "in config exports and audit logs."
            ),
            recommendation=(
                "Rename rules using role-based or functional identifiers (e.g. 'IT-Admin-RDP-Access' "
                "instead of 'Juan Dela Cruz RDP'). "
                "Under the Philippines Data Privacy Act (RA 10173) and GDPR Article 5(1)(c), "
                "personal data must not be processed beyond what is necessary. "
                "Config backup files are routinely shared with vendors and auditors — embedded personal "
                "names create unnecessary PII exposure. "
                "Aligns with OWASP A02:2021 – Cryptographic Failures (sensitive data exposure) and "
                "NIST SP 800-53 Rev 5 AC-2 (Account Management) which requires role-based access labelling."
            ),
            location=(
                f"{_FW_NAV}\n"
                "→ Click the rule name → Edit → rename the rule to a functional/role-based identifier → Save"
            ),
            references=[
                "Philippines Republic Act 10173 – Data Privacy Act of 2012",
                "GDPR Article 5(1)(c) – Data Minimisation",
                "NIST SP 800-53 Rev 5 AC-2 – Account Management",
                "OWASP A02:2021 – Cryptographic Failures (sensitive data in config exports)",
            ],
            affected=[_label(r) for r in pii_rules],
            affected_rules=pii_rules,
            exploitability="Low", impact_scope="Local", exposure="Internal",
        ))

    # ── IPS policy not assigned to WAN/DMZ accept rules ──────────────────────
    if no_ips_rules:
        findings.append(Finding(
            severity=Severity.HIGH,
            category="Firewall Rules",
            title="WAN/DMZ accept rules with no IPS policy assigned",
            detail=(
                "These rules permit inbound traffic from external or DMZ zones but have no "
                "Intrusion Prevention System (IPS) policy attached. Without IPS, exploit attempts "
                "against permitted services pass through the firewall completely uninspected — "
                "the global IPS toggle being on is insufficient if individual rules do not reference a policy."
            ),
            recommendation=(
                "Edit each affected rule and assign an IPS policy under 'Security features'. "
                "Use the most restrictive policy appropriate for the service (e.g. 'LAN to DMZ' or "
                "'General Threat Protection'). "
                "Rules without IPS directly enable MITRE ATT&CK T1190 (Exploit Public-Facing Application) "
                "and T1203 (Exploitation for Client Execution) — known CVEs are exploited without detection. "
                "Aligns with OWASP A06:2021 – Vulnerable and Outdated Components."
            ),
            location=(
                f"{_FW_NAV}\n"
                "→ Click the rule name → Edit → scroll to 'Security features' "
                "→ select an IPS policy from the dropdown → Save"
            ),
            references=[
                "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                "MITRE ATT&CK T1203 – Exploitation for Client Execution",
                "OWASP A06:2021 – Vulnerable and Outdated Components",
                "CIS Control 13.3 – Deploy a Network Intrusion Detection Solution",
                "NIST SP 800-94 – Guide to Intrusion Detection and Prevention Systems",
            ],
            affected=[_label(r) for r in no_ips_rules],
            affected_rules=no_ips_rules,
            exploitability="High", impact_scope="Network", exposure="External",
            detectability=_detectability(no_ips_rules),
        ))

    # ── Shadowed rules ────────────────────────────────────────────────────────
    if shadowed_rules:
        shadowed_only = [r for r, _ in shadowed_rules]
        shadow_detail = "; ".join(
            f"{_label(r)} shadowed by {_label(broad)}"
            for r, broad in shadowed_rules[:5]
        )
        if len(shadowed_rules) > 5:
            shadow_detail += f" (and {len(shadowed_rules) - 5} more)"
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="Firewall Rules",
            title="Shadowed rules detected — rules that can never be matched",
            detail=(
                "One or more rules appear after a broader any-to-any rule that already matches "
                "the same traffic. Because Sophos evaluates rules top-down (first match wins), "
                "these rules are permanently bypassed and their intent — whether to block or allow — "
                f"is never enforced. Detail: {shadow_detail}."
            ),
            recommendation=(
                "Review policy order and move specific rules ABOVE the broader any-to-any rule, "
                "or replace the any-to-any rule with explicit per-service entries. "
                "Shadowed deny rules are especially dangerous: an admin may believe traffic is blocked "
                "when it is actually accepted by the earlier any-to-any permit. "
                "This is a common configuration path that enables MITRE ATT&CK T1562.004 "
                "(Impair Defenses: Disable or Modify System Firewall) — the firewall policy "
                "appears correct but a rule never fires. "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            location=(
                f"{_FW_NAV}\n"
                "→ Drag the specific rule to a position ABOVE the any-to-any rule → Save\n"
                "Or remove the any-to-any rule and replace with explicit permit entries"
            ),
            references=[
                "MITRE ATT&CK T1562.004 – Impair Defenses: Disable or Modify System Firewall",
                "OWASP A05:2021 – Security Misconfiguration",
                "NIST SP 800-41 Rev 1 §3.3 – Firewall Rule Order",
                "CIS Control 4.1 – Establish and Maintain a Secure Configuration Process",
            ],
            affected=[f"{_label(r)} (shadowed by {_label(broad)})" for r, broad in shadowed_rules],
            affected_rules=shadowed_only,
            exploitability="Low", impact_scope="Network", exposure="Internal",
            detectability=_detectability(shadowed_only),
        ))

    # ── Duplicate rules ───────────────────────────────────────────────────────
    if duplicate_rules:
        dup_only = [r for r, _ in duplicate_rules]
        findings.append(Finding(
            severity=Severity.LOW,
            category="Firewall Rules",
            title="Duplicate firewall rules detected",
            detail=(
                "Two or more rules have identical source zone, destination zone, source network, "
                "destination network, service, and action. Duplicate rules add policy clutter, "
                "make auditing harder, and increase the risk that a change to one copy is not "
                "reflected in the other, causing inconsistent enforcement."
            ),
            recommendation=(
                "Remove or consolidate duplicate rules. Keep only one authoritative entry for each "
                "traffic flow. Review both copies before deleting to confirm they are truly identical. "
                "Duplicate rules can also mask intentional differences and obscure MITRE ATT&CK "
                "T1562.004 (Disable or Modify System Firewall) attempts if an attacker inserts "
                "a near-duplicate with different security profiles. "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            location=(
                f"{_FW_NAV}\n"
                "→ Identify and delete the duplicate rule → Save"
            ),
            references=[
                "MITRE ATT&CK T1562.004 – Impair Defenses: Disable or Modify System Firewall",
                "OWASP A05:2021 – Security Misconfiguration",
                "CIS Control 4.1 – Establish and Maintain a Secure Configuration Process",
            ],
            affected=[
                f"{_label(r)} — duplicate of {_label(orig)}"
                for r, orig in duplicate_rules
            ],
            affected_rules=dup_only,
            exploitability="Low", impact_scope="Local", exposure="Internal",
            detectability=_detectability(dup_only),
        ))

    return findings

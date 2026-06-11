"""Config checks — Port exposure and dangerous service vulnerability analysis.

Cross-references firewall/NAT rules with service definitions to identify
dangerous ports that are permitted through the firewall, especially from
untrusted zones (WAN/Internet).

Each finding references the relevant MITRE ATT&CK technique(s) and
OWASP Top 10 2021 category in the recommendation and references fields.
"""
from .models import Finding, Severity

_S = "Config — Port Exposure"

# ── Zone classification ───────────────────────────────────────────────────────
_WAN_ZONES  = {"wan", "internet", "untrust", "external", "outside", "dmz-wan", "public"}
_LAN_ZONES  = {"lan", "internal", "trust", "users", "inside", "corporate", "employee"}
_ANY_ZONES  = {"any", "all", "*"}

def _is_wan(zones: list) -> bool:
    return any(z.lower() in _WAN_ZONES | _ANY_ZONES for z in zones)

def _is_lan(zones: list) -> bool:
    return any(z.lower() in _LAN_ZONES | _ANY_ZONES for z in zones)


# ── Port catalogue ────────────────────────────────────────────────────────────
# Each entry: port_number -> (label, severity, reason)

_CLEARTEXT_REMOTE = {
    23:  ("Telnet",   Severity.CRITICAL, "Cleartext terminal — credentials transmitted in plaintext"),
    512: ("rexec",    Severity.CRITICAL, "BSD r-protocol — cleartext remote execution, no encryption"),
    513: ("rlogin",   Severity.CRITICAL, "BSD r-protocol — cleartext remote login, no encryption"),
    514: ("rsh",      Severity.CRITICAL, "BSD r-protocol — cleartext remote shell, no encryption"),
    79:  ("Finger",   Severity.HIGH,     "Finger daemon — leaks OS user information to anyone"),
    69:  ("TFTP",     Severity.HIGH,     "TFTP — unauthenticated, cleartext file transfer"),
    21:  ("FTP",      Severity.HIGH,     "FTP control channel — cleartext credentials; use SFTP/FTPS"),
    20:  ("FTP-Data", Severity.MEDIUM,   "FTP data channel — cleartext; pairs with port 21"),
    19:  ("Chargen",  Severity.MEDIUM,   "Chargen — can be used in amplification DoS attacks"),
    7:   ("Echo",     Severity.MEDIUM,   "Echo service — amplification attack surface"),
    13:  ("Daytime",  Severity.LOW,      "Daytime service — information disclosure (system time)"),
    37:  ("Time",     Severity.LOW,      "Time protocol — unauthenticated time source"),
}

_DATABASE = {
    3306:  ("MySQL/MariaDB",   Severity.CRITICAL, "Database port — direct internet exposure enables credential brute-force and data theft"),
    1433:  ("MSSQL",           Severity.CRITICAL, "SQL Server — directly exposed, high-value ransomware and exfiltration target"),
    1434:  ("MSSQL Browser",   Severity.HIGH,     "SQL Server Browser — leaks instance information"),
    5432:  ("PostgreSQL",      Severity.CRITICAL, "PostgreSQL — direct exposure, lateral movement risk"),
    1521:  ("Oracle DB",       Severity.CRITICAL, "Oracle DB listener — direct exposure, high-value target"),
    1522:  ("Oracle DB alt",   Severity.HIGH,     "Oracle DB alternate listener"),
    6379:  ("Redis",           Severity.CRITICAL, "Redis — frequently deployed without authentication; trivial RCE"),
    27017: ("MongoDB",         Severity.CRITICAL, "MongoDB — default has no authentication; mass exploitation history"),
    27018: ("MongoDB shard",   Severity.HIGH,     "MongoDB shard server"),
    27019: ("MongoDB config",  Severity.HIGH,     "MongoDB config server"),
    9042:  ("Cassandra",       Severity.HIGH,     "Cassandra CQL — unauthenticated by default in older versions"),
    9160:  ("Cassandra Thrift",Severity.HIGH,     "Cassandra Thrift API — legacy, unauthenticated"),
    11211: ("Memcached",       Severity.CRITICAL, "Memcached — no authentication; used in massive DDoS amplification (2018 GitHub attack)"),
    9200:  ("Elasticsearch",   Severity.CRITICAL, "Elasticsearch HTTP API — no auth by default; mass data breaches attributed to exposure"),
    9300:  ("Elasticsearch cluster", Severity.HIGH, "Elasticsearch cluster port — node communication, no auth"),
    5984:  ("CouchDB",         Severity.HIGH,     "CouchDB admin interface — default creds; Futon/Fauxton exposed"),
    8086:  ("InfluxDB",        Severity.HIGH,     "InfluxDB HTTP API — time-series DB, often no auth"),
    7474:  ("Neo4j",           Severity.HIGH,     "Neo4j browser — graph DB, often no auth in default install"),
    5000:  ("Sybase/Docker",   Severity.MEDIUM,   "Sybase DB or Docker Registry — context-dependent risk"),
    50000: ("IBM DB2",         Severity.HIGH,     "IBM DB2 — direct exposure, enterprise database"),
}

_REMOTE_ACCESS = {
    3389:  ("RDP",            Severity.CRITICAL, "RDP directly exposed — BlueKeep/DejaBlue class vulnerabilities; top ransomware entry vector"),
    5900:  ("VNC",            Severity.CRITICAL, "VNC — graphical remote access; often no/weak auth"),
    5901:  ("VNC :1",         Severity.HIGH,     "VNC display 1"),
    5902:  ("VNC :2",         Severity.HIGH,     "VNC display 2"),
    5903:  ("VNC :3",         Severity.HIGH,     "VNC display 3"),
    5985:  ("WinRM HTTP",     Severity.HIGH,     "WinRM over HTTP — Windows remote management, cleartext"),
    5986:  ("WinRM HTTPS",    Severity.MEDIUM,   "WinRM over HTTPS — encrypted but still high-value target"),
    6000:  ("X11",            Severity.HIGH,     "X11 display server — remote desktop capture/injection"),
    6001:  ("X11 :1",         Severity.HIGH,     "X11 display 1"),
    2598:  ("Citrix ICA",     Severity.MEDIUM,   "Citrix ICA — legacy remote access"),
    1494:  ("Citrix ICA alt", Severity.MEDIUM,   "Citrix ICA alternate port"),
}

_SMB_FILE = {
    445:  ("SMB",          Severity.CRITICAL, "SMB directly exposed — EternalBlue/WannaCry/NotPetya vector; never expose to internet"),
    139:  ("NetBIOS SMB",  Severity.CRITICAL, "NetBIOS over TCP — legacy SMB; same risk as port 445"),
    137:  ("NetBIOS NS",   Severity.HIGH,     "NetBIOS Name Service — information disclosure"),
    138:  ("NetBIOS DGM",  Severity.HIGH,     "NetBIOS Datagram — lateral movement risk"),
    2049: ("NFS",          Severity.HIGH,     "NFS — no encryption/authentication at network layer; file system exposure"),
    111:  ("RPCbind",      Severity.HIGH,     "RPCbind/portmapper — leaks RPC service list; required for NFS attack chain"),
}

_CLOUD_CONTAINER = {
    2375:  ("Docker API (plain)", Severity.CRITICAL, "Docker daemon exposed without TLS — full host compromise via container escape"),
    2376:  ("Docker API (TLS)",   Severity.HIGH,     "Docker daemon with TLS — verify cert validation is enforced"),
    6443:  ("Kubernetes API",     Severity.CRITICAL, "Kubernetes API server — full cluster control if exposed"),
    8080:  ("Kubernetes alt",     Severity.HIGH,     "Kubernetes alternate API/dashboard port"),
    10250: ("Kubelet",            Severity.HIGH,     "Kubelet API — can be used to exec into pods"),
    2379:  ("etcd client",        Severity.CRITICAL, "etcd — Kubernetes backing store; holds all cluster secrets"),
    2380:  ("etcd peer",          Severity.HIGH,     "etcd peer port — cluster communication"),
    9000:  ("Portainer/SonarQube",Severity.MEDIUM,   "Portainer Docker UI or SonarQube — admin interfaces"),
    8443:  ("Alt HTTPS/K8s",      Severity.LOW,      "Alternate HTTPS port — verify intended exposure"),
}

_ICS_SCADA = {
    502:   ("Modbus",      Severity.CRITICAL, "Modbus TCP — ICS/SCADA protocol; no authentication, full device control possible"),
    102:   ("S7/ISO-TSAP", Severity.CRITICAL, "Siemens S7 PLC protocol — direct PLC access; Stuxnet used this attack surface"),
    44818: ("EtherNet/IP", Severity.CRITICAL, "EtherNet/IP — Rockwell/Allen-Bradley PLC protocol; unauthenticated read/write"),
    20000: ("DNP3",        Severity.CRITICAL, "DNP3 — SCADA protocol for electric/water utilities; no authentication"),
    2404:  ("IEC 60870-5-104", Severity.CRITICAL, "IEC 104 — power grid SCADA protocol; unauthenticated"),
    47808: ("BACnet",      Severity.HIGH,     "BACnet — building automation (HVAC, access control); widely exploited"),
    1883:  ("MQTT",        Severity.HIGH,     "MQTT (cleartext) — IoT messaging; often no auth; broker compromise"),
    8883:  ("MQTT TLS",    Severity.MEDIUM,   "MQTT over TLS — verify broker enforces authentication"),
    1911:  ("Niagara Fox",  Severity.HIGH,    "Tridium Niagara — building automation; known CVEs"),
    4840:  ("OPC-UA",      Severity.MEDIUM,   "OPC Unified Architecture — industrial data exchange"),
}

_MGMT_MONITORING = {
    161:  ("SNMP",      Severity.HIGH,   "SNMP from WAN — community strings can expose full device MIB; v1/v2c cleartext"),
    162:  ("SNMP Trap", Severity.MEDIUM, "SNMP Trap — unsolicited from WAN; spoofing risk"),
    623:  ("IPMI/BMC",  Severity.CRITICAL,"IPMI — baseboard management; CipherZero vulnerability; out-of-band full server access"),
    664:  ("IPMI alt",  Severity.HIGH,   "IPMI alternate port"),
    830:  ("NETCONF",   Severity.MEDIUM, "NETCONF over SSH — network device management"),
    8161: ("ActiveMQ",  Severity.HIGH,   "ActiveMQ admin — critical CVEs including Log4Shell-adjacent"),
}

# Consolidated lookup: port -> (label, severity, reason, category_tag)
_ALL_DANGEROUS: dict[int, tuple] = {}
for _cat, _entries in (
    ("Cleartext Remote",   _CLEARTEXT_REMOTE),
    ("Database",           _DATABASE),
    ("Remote Access",      _REMOTE_ACCESS),
    ("File Sharing",       _SMB_FILE),
    ("Cloud/Container",    _CLOUD_CONTAINER),
    ("ICS/SCADA",          _ICS_SCADA),
    ("Management",         _MGMT_MONITORING),
):
    for _port, (_label, _sev, _reason) in _entries.items():
        _ALL_DANGEROUS[_port] = (_label, _sev, _reason, _cat)


def _parse_port_range(port_str: str) -> set[int]:
    """Expand '80', '80:443', '1:1024' etc. to a set of port ints (capped at 1024 members)."""
    ports: set[int] = set()
    if not port_str:
        return ports
    for segment in port_str.replace(",", " ").split():
        segment = segment.strip()
        if ":" in segment or "-" in segment:
            sep = ":" if ":" in segment else "-"
            try:
                lo, hi = segment.split(sep, 1)
                lo_i, hi_i = int(lo), int(hi)
                # cap range expansion to avoid memory explosion
                if hi_i - lo_i <= 2000:
                    ports.update(range(lo_i, hi_i + 1))
                else:
                    # just record boundaries
                    ports.add(lo_i)
                    ports.add(hi_i)
                    ports.add(-1)  # sentinel: range too wide to enumerate
            except ValueError:
                pass
        else:
            try:
                ports.add(int(segment))
            except ValueError:
                pass
    return ports


def _resolve_rule_ports(rule: dict, service_defs: dict) -> set[int]:
    """Return the set of destination ports covered by a rule's service list."""
    ports: set[int] = set()
    for svc_name in rule.get("services", []):
        if svc_name.lower() in ("any", "all", "*"):
            return {-1}  # -1 = wildcard
        defn = service_defs.get(svc_name)
        if defn:
            ports |= _parse_port_range(defn.get("dst_port", ""))
        # Fallback: try to infer from well-known service names
        ports |= _infer_ports_from_name(svc_name)
    return ports


# Hardcoded name→port for Sophos built-in services we care about
_BUILTIN = {
    "rdp": {3389}, "remote desktop": {3389},
    "telnet": {23},
    "ftp": {20, 21}, "ftp-data": {20},
    "tftp": {69},
    "ssh": {22},
    "http": {80}, "https": {443},
    "smb": {445, 139}, "netbios": {137, 138, 139},
    "nfs": {2049, 111},
    "snmp": {161, 162},
    "vnc": {5900, 5901, 5902, 5903},
    "winrm": {5985, 5986},
    "mysql": {3306},
    "mssql": {1433, 1434}, "ms-sql": {1433, 1434}, "sql server": {1433, 1434},
    "postgresql": {5432}, "postgres": {5432},
    "oracle": {1521, 1522},
    "redis": {6379},
    "mongodb": {27017, 27018, 27019},
    "memcached": {11211},
    "elasticsearch": {9200, 9300},
    "modbus": {502},
    "bacnet": {47808},
    "mqtt": {1883, 8883},
    "dnp3": {20000},
    "docker": {2375, 2376},
    "kubernetes": {6443},
    "etcd": {2379, 2380},
    "ipmi": {623, 664},
}


def _infer_ports_from_name(name: str) -> set[int]:
    key = name.lower()
    for k, v in _BUILTIN.items():
        if k in key or key in k:
            return v
    return set()


def _rule_label(r: dict) -> str:
    pos = r.get("policy_index") or r.get("position") or "?"
    name = r.get("name") or "(unnamed)"
    return f"#{pos} {name}"


def run(cfg) -> list[Finding]:
    findings: list[Finding] = []
    service_defs = cfg.service_defs

    # ── 1. WAN-facing accept rules with dangerous ports ───────────────────────
    # Group hits by (port, severity) so we produce one finding per dangerous port
    # rather than one per rule.
    port_hits: dict[int, list[dict]] = {}  # port -> list of offending rules

    for rule in cfg.firewall_rules:
        if rule.get("action", "").lower() not in ("accept", "allow"):
            continue
        if not _is_wan(rule.get("src_zones", [])):
            continue

        ports = _resolve_rule_ports(rule, service_defs)
        if -1 in ports:
            # Already flagged as any-service in firewall_rules.py; skip here
            continue

        for port in ports:
            if port in _ALL_DANGEROUS:
                port_hits.setdefault(port, []).append(rule)

    # Emit one finding per dangerous port group
    for port, rules in sorted(port_hits.items()):
        label, sev, reason, cat_tag = _ALL_DANGEROUS[port]
        affected_rules = []
        for r in rules:
            rc = dict(r)
            rc["_flagged_service"] = f"Port {port}/{label}"
            affected_rules.append(rc)

        # Build MITRE/OWASP references per port category
        _port_refs = {
            "Cleartext Remote":  ["MITRE ATT&CK T1040 – Network Sniffing", "MITRE ATT&CK T1557 – Adversary-in-the-Middle", "OWASP A02:2021 – Cryptographic Failures"],
            "Database":          ["MITRE ATT&CK T1190 – Exploit Public-Facing Application", "MITRE ATT&CK T1078 – Valid Accounts", "OWASP A05:2021 – Security Misconfiguration"],
            "Remote Access":     ["MITRE ATT&CK T1021.001 – Remote Desktop Protocol", "MITRE ATT&CK T1133 – External Remote Services", "MITRE ATT&CK T1190 – Exploit Public-Facing Application", "OWASP A05:2021 – Security Misconfiguration"],
            "File Sharing":      ["MITRE ATT&CK T1021.002 – SMB/Windows Admin Shares", "MITRE ATT&CK T1570 – Lateral Tool Transfer", "OWASP A05:2021 – Security Misconfiguration"],
            "Cloud/Container":   ["MITRE ATT&CK T1190 – Exploit Public-Facing Application", "MITRE ATT&CK T1611 – Escape to Host", "OWASP A05:2021 – Security Misconfiguration"],
            "ICS/SCADA":         ["MITRE ATT&CK ICS T0855 – Unauthorized Command Message", "MITRE ATT&CK T1190 – Exploit Public-Facing Application", "OWASP A05:2021 – Security Misconfiguration"],
            "Management":        ["MITRE ATT&CK T1040 – Network Sniffing", "MITRE ATT&CK T1046 – Network Service Discovery", "OWASP A05:2021 – Security Misconfiguration"],
        }
        refs = _port_refs.get(cat_tag, ["OWASP A05:2021 – Security Misconfiguration"])

        findings.append(Finding(
            severity=sev,
            category=_S,
            title=f"Port {port} ({label}) permitted inbound from WAN",
            detail=(
                f"{reason}. "
                f"{'One firewall rule allows' if len(rules)==1 else f'{len(rules)} firewall rules allow'} "
                f"traffic destined for port {port} from WAN/untrusted zones."
            ),
            recommendation=(
                f"Block inbound access to port {port} from untrusted networks. "
                f"If {label} is required, restrict to specific source IPs, enforce strong authentication, "
                f"and place behind VPN. "
                f"Aligns with MITRE ATT&CK Mitigation M1030 (Network Segmentation) and "
                f"M1042 (Disable or Remove Feature or Program). "
                f"Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            location=(
                f"Firewall → Rules and policies → Firewall rules\n"
                f"→ Review rules permitting port {port} from WAN → restrict source or block → Save"
            ),
            references=refs + [
                "MITRE ATT&CK Mitigation M1030 – Network Segmentation",
                "MITRE ATT&CK Mitigation M1042 – Disable or Remove Feature or Program",
                "CIS Control 4.4 – Implement and Manage a Firewall on Servers",
            ],
            affected_rules=affected_rules,
        ))

    # ── 2. LAN rules with database/management ports exposed broadly ──────────
    # Flag database and ICS ports accessible from ALL internal hosts with no
    # destination restriction (dst_networks contains Any/All).
    _INTERNAL_SENSITIVE = {**_DATABASE, **_ICS_SCADA}

    db_hits: dict[int, list[dict]] = {}
    for rule in cfg.firewall_rules:
        if rule.get("action", "").lower() not in ("accept", "allow"):
            continue
        src_z = rule.get("src_zones", [])
        dst_n = rule.get("dst_networks", [])
        # Only flag if source is from LAN zones
        if not _is_lan(src_z):
            continue
        # Only flag if destination is Any/All (no restriction)
        if not any(n.lower() in ("any", "all", "*") for n in dst_n) and dst_n:
            continue

        ports = _resolve_rule_ports(rule, service_defs)
        if -1 in ports:
            continue
        for port in ports:
            if port in _INTERNAL_SENSITIVE:
                db_hits.setdefault(port, []).append(rule)

    for port, rules in sorted(db_hits.items()):
        label, sev, reason, cat_tag = _INTERNAL_SENSITIVE[port]
        # Downgrade severity by one level for LAN-only (still dangerous)
        sev_map = {
            Severity.CRITICAL: Severity.HIGH,
            Severity.HIGH:     Severity.MEDIUM,
            Severity.MEDIUM:   Severity.LOW,
            Severity.LOW:      Severity.LOW,
        }
        adj_sev = sev_map.get(sev, sev)
        affected_rules = [dict(r) for r in rules]

        findings.append(Finding(
            severity=adj_sev,
            category=_S,
            title=f"Port {port} ({label}) accessible from internal network without destination restriction",
            detail=(
                f"{label} (port {port}) is reachable from internal zones with no destination host restriction. "
                f"A compromised internal host or rogue device can reach {label} on any host in the destination network."
            ),
            recommendation=(
                f"Restrict firewall rules permitting port {port} to specific source hosts/groups "
                f"and explicitly named destination server IPs. Avoid using 'Any' as a destination for {label}. "
                f"Broad internal access supports MITRE ATT&CK TA0008 (Lateral Movement) — "
                f"a compromised workstation can pivot to every {label} server in the network. "
                f"Aligns with OWASP A01:2021 – Broken Access Control."
            ),
            references=[
                "MITRE ATT&CK TA0008 – Lateral Movement",
                "MITRE ATT&CK T1021 – Remote Services",
                "MITRE ATT&CK Mitigation M1030 – Network Segmentation",
                "OWASP A01:2021 – Broken Access Control",
                "CIS Control 12.2 – Establish and Maintain a Secure Network Architecture",
            ],
            location=(
                f"Firewall → Rules and policies → Firewall rules\n"
                f"→ Edit rules for port {port} → change DestinationNetworks to specific server IPs → Save"
            ),
            affected_rules=affected_rules,
        ))

    # ── 3. Broad port range in accept rules ───────────────────────────────────
    wide_rules = []
    for rule in cfg.firewall_rules:
        if rule.get("action", "").lower() not in ("accept", "allow"):
            continue
        for svc_name in rule.get("services", []):
            if svc_name.lower() in ("any", "all", "*"):
                continue  # covered in firewall_rules.py
            defn = service_defs.get(svc_name)
            if not defn:
                continue
            dst = defn.get("dst_port", "")
            if ":" in dst or "-" in dst:
                try:
                    sep = ":" if ":" in dst else "-"
                    lo, hi = dst.split(sep, 1)
                    if int(hi) - int(lo) >= 1000:
                        wide_rules.append((rule, svc_name, dst))
                        break
                except ValueError:
                    pass

    if wide_rules:
        affected = [f"{_rule_label(r)} (service '{s}' → ports {p})" for r, s, p in wide_rules]
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="Accept rules with overly broad port ranges (≥1000 ports)",
            detail=(
                "Service objects permitting 1000 or more destination ports in a single rule grant far more "
                "access than necessary and make policy review difficult. Attacker movement is less constrained."
            ),
            recommendation=(
                "Replace broad port-range service objects with specific named services. "
                "Apply the principle of least privilege — permit only the exact ports required."
            ),
            location=(
                "Hosts and services → Services → review service objects with large port ranges\n"
                "→ split into specific services → update firewall rules → Save"
            ),
            affected=affected,
        ))

    # ── 4. NAT DNAT rules forwarding to dangerous ports ───────────────────────
    # Look for DNAT entries whose translated destination port hits the catalogue.
    nat_hits: dict[int, list[str]] = {}
    for rule in cfg.nat_rules:
        # Extract translated/original destination port from NAT rule dict
        # Sophos XG DNAT fields vary by firmware; try multiple key names.
        nat_type = (
            str(rule.get("NATType", ""))
            or str(rule.get("Type", ""))
            or str(rule.get("NatType", ""))
        ).lower()
        if "dnat" not in nat_type and "destination" not in nat_type and "inbound" not in nat_type:
            continue

        for key in ("TranslatedDestinationPort", "TranslatedPort", "DstPort",
                    "OriginalDestinationPort", "InboundPort", "ExternalPort",
                    "MappedPort"):
            port_val = str(rule.get(key, "")).strip()
            if not port_val:
                continue
            for p in _parse_port_range(port_val):
                if p != -1 and p in _ALL_DANGEROUS:
                    name = rule.get("Name") or rule.get("RuleName") or "unnamed"
                    nat_hits.setdefault(p, []).append(str(name))
            break

    for port, rule_names in sorted(nat_hits.items()):
        label, sev, reason, cat_tag = _ALL_DANGEROUS[port]
        # Already covered by nat.py for RDP specifically, but include all others
        if port == 3389:
            continue  # nat.py already raises CRITICAL for this
        findings.append(Finding(
            severity=sev,
            category=_S,
            title=f"NAT rule forwarding to port {port} ({label})",
            detail=(
                f"A DNAT/port-forward rule directs inbound traffic to port {port} ({label}). "
                f"{reason}."
            ),
            recommendation=(
                f"Review whether exposing {label} via NAT is necessary. "
                f"Place behind VPN if possible, restrict source IPs, and ensure the destination "
                f"service is fully patched and hardened."
            ),
            location=(
                "Firewall → Rules and policies → NAT rules\n"
                f"→ Review DNAT rules for port {port} → restrict original source IPs → Save"
            ),
            affected=rule_names,
        ))

    return findings

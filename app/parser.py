"""Sophos XG/SFOS XML config parser."""
from lxml import etree
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SophosConfig:
    # Policy
    firewall_rules: list[dict]  = field(default_factory=list)
    nat_rules:      list[dict]  = field(default_factory=list)
    vpn_ipsec:      list[dict]  = field(default_factory=list)
    vpn_ssl:        list[dict]  = field(default_factory=list)
    vpn_pptp:       dict        = field(default_factory=dict)
    # Administration
    admin_settings: dict        = field(default_factory=dict)
    device_access:  list[dict]  = field(default_factory=list)
    admin_profiles: list[dict]  = field(default_factory=list)
    local_users:    list[dict]  = field(default_factory=list)
    auth_servers:   list[dict]  = field(default_factory=list)  # RADIUS/LDAP/AD
    mfa_settings:   dict        = field(default_factory=dict)
    password_policy: dict       = field(default_factory=dict)
    # Network
    interfaces:     list[dict]  = field(default_factory=list)
    network_zones:  list[dict]  = field(default_factory=list)
    routing:        list[dict]  = field(default_factory=list)
    # System
    system_settings: dict       = field(default_factory=dict)
    ntp_servers:    list[dict]  = field(default_factory=list)
    dns_settings:   dict        = field(default_factory=dict)
    snmp_settings:  dict        = field(default_factory=dict)
    ha_settings:    dict        = field(default_factory=dict)
    backup_settings: dict       = field(default_factory=dict)
    notification_settings: dict = field(default_factory=dict)
    update_settings: dict       = field(default_factory=dict)
    # Security
    syslog_servers: list[dict]  = field(default_factory=list)
    certificates:   list[dict]  = field(default_factory=list)
    dos_settings:   dict        = field(default_factory=dict)
    ips_settings:   dict        = field(default_factory=dict)
    ips_policies:   list[dict]  = field(default_factory=list)
    av_settings:    dict        = field(default_factory=dict)
    sandbox_settings: dict      = field(default_factory=dict)
    web_filter:     list[dict]  = field(default_factory=list)
    app_control:    list[dict]  = field(default_factory=list)
    ssl_inspection: dict        = field(default_factory=dict)
    email_settings: dict        = field(default_factory=dict)
    # Misc
    services:       list[dict]  = field(default_factory=list)
    service_defs:   dict        = field(default_factory=dict)  # name -> {ports, protocol}
    raw_sections:   dict[str,int] = field(default_factory=dict)


def _text(el, tag: str, default: str = "") -> str:
    child = el.find(tag)
    return child.text.strip() if child is not None and child.text else default


def _children_text(el, tag: str) -> list[str]:
    return [c.text.strip() for c in el.findall(tag) if c.text]


def _el_to_dict(el) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for child in el:
        if len(child) == 0:
            d[child.tag] = child.text.strip() if child.text else ""
        else:
            existing = d.get(child.tag)
            item = _el_to_dict(child)
            if existing is None:
                d[child.tag] = item
            elif isinstance(existing, list):
                existing.append(item)
            else:
                d[child.tag] = [existing, item]
    return d


def _first(root, *xpaths) -> Any:
    for xp in xpaths:
        el = root.find(xp)
        if el is not None:
            return el
    return None


def parse(xml_bytes: bytes) -> SophosConfig:
    try:
        _parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
        root = etree.fromstring(xml_bytes, _parser)
    except etree.XMLSyntaxError as exc:
        raise ValueError(f"Invalid XML: {exc}") from exc

    cfg = SophosConfig()

    for child in root:
        cfg.raw_sections[child.tag] = cfg.raw_sections.get(child.tag, 0) + 1

    # ── Firewall Rules ────────────────────────────────────────────────────────
    for idx, rule in enumerate(root.iter("FirewallRule")):
        cfg.firewall_rules.append({
            "id":           rule.get("id") or rule.get("Id") or _text(rule, "Id") or _text(rule, "RuleID"),
            "policy_index": idx + 1,
            "name":         _text(rule, "Name"),
            "status":       _text(rule, "Status", "Enable"),
            "action":       _text(rule, "NetworkPolicy/Action") or _text(rule, "Action"),
            "src_zones":    _children_text(rule, "SourceZones/Zone")    or _children_text(rule, "SourceZone"),
            "dst_zones":    _children_text(rule, "DestinationZones/Zone") or _children_text(rule, "DestinationZone"),
            "src_networks": _children_text(rule, "SourceNetworks/Network") or _children_text(rule, "SourceNetwork"),
            "dst_networks": _children_text(rule, "DestinationNetworks/Network") or _children_text(rule, "DestinationNetwork"),
            "services":     _children_text(rule, "Services/Service") or _children_text(rule, "Service"),
            "log_traffic":  (
                _text(rule, "LogTraffic") or _text(rule, "Log") or
                _text(rule, "PolicyLog") or _text(rule, "TrafficLog") or ""
            ),
            "schedule":     _text(rule, "Schedule", "All the time"),
            "description":  _text(rule, "Description"),
            "position":     _text(rule, "Position"),
            "ips_policy":   _text(rule, "IPSPolicy") or _text(rule, "IntrusionPrevention"),
            "web_filter":   _text(rule, "WebFilter") or _text(rule, "WebPolicy"),
            "app_control":  _text(rule, "ApplicationControl"),
            "av_profile":   _text(rule, "AVPolicy") or _text(rule, "AntiVirusPolicy"),
        })

    # ── NAT Rules ─────────────────────────────────────────────────────────────
    for rule in root.iter("NATRule"):
        cfg.nat_rules.append(_el_to_dict(rule))

    # ── IPSec VPN ─────────────────────────────────────────────────────────────
    for policy in root.iter("IPsecPolicy"):
        cfg.vpn_ipsec.append({
            "name":       _text(policy, "Name"),
            "key_exchange": _text(policy, "KeyExchange"),
            "auth_mode":  _text(policy, "AuthenticationMode"),
            "phase1_enc": _text(policy, "Phase1EncryptionAlgorithm") or _text(policy, "EncryptionAlgorithm"),
            "phase1_auth": _text(policy, "Phase1AuthenticationAlgorithm") or _text(policy, "AuthenticationAlgorithm"),
            "phase1_dh":  _text(policy, "Phase1DHGroup") or _text(policy, "DHGroup"),
            "phase2_enc": _text(policy, "Phase2EncryptionAlgorithm"),
            "phase2_auth": _text(policy, "Phase2AuthenticationAlgorithm"),
            "phase2_pfs": _text(policy, "Phase2PFSGroup"),
            "lifetime":   _text(policy, "KeyLife") or _text(policy, "Lifetime"),
        })

    # ── SSL VPN ───────────────────────────────────────────────────────────────
    for policy in root.iter("SSLVPNPolicy"):
        cfg.vpn_ssl.append(_el_to_dict(policy))

    # ── PPTP VPN ──────────────────────────────────────────────────────────────
    pptp_el = _first(root, ".//PPTPSettings", ".//PPTP", ".//PPTPServer", ".//L2TPSettings",
                     ".//RemoteAccessVPN/PPTP", ".//RemoteAccessVPN/L2TP")
    if pptp_el is not None:
        cfg.vpn_pptp = _el_to_dict(pptp_el)
        cfg.vpn_pptp["_tag"] = pptp_el.tag  # preserve element name for type detection

    # ── Administration ────────────────────────────────────────────────────────
    admin_el = _first(root, ".//AdministrationSettings", ".//Administration")
    if admin_el is not None:
        cfg.admin_settings = _el_to_dict(admin_el)

    for da in root.iter("DeviceAccess"):
        cfg.device_access.append(_el_to_dict(da))

    for p in root.iter("AdministratorProfile"):
        cfg.admin_profiles.append(_el_to_dict(p))

    for u in root.iter("LocalServiceACL"):
        cfg.local_users.append(_el_to_dict(u))

    for u in root.iter("User"):
        role = _text(u, "Group") or _text(u, "Profile")
        cfg.local_users.append({
            "name":   _text(u, "Name") or _text(u, "Username"),
            "status": _text(u, "Status", "Enable"),
            "role":   role,
            "email":  _text(u, "EmailAddress") or _text(u, "Email"),
        })

    # ── Auth Servers (RADIUS / LDAP / AD) ────────────────────────────────────
    for tag in ("RADIUSServer", "LDAPServer", "ActiveDirectory", "AuthServer"):
        for s in root.iter(tag):
            d = _el_to_dict(s)
            d["_type"] = tag
            cfg.auth_servers.append(d)

    # ── MFA ───────────────────────────────────────────────────────────────────
    mfa_el = _first(root, ".//MFA", ".//TwoFactorAuth", ".//TOTPSettings")
    if mfa_el is not None:
        cfg.mfa_settings = _el_to_dict(mfa_el)

    # ── Password Policy ───────────────────────────────────────────────────────
    pp_el = _first(root, ".//PasswordPolicy", ".//PasswordComplexity", ".//AdminPasswordPolicy")
    if pp_el is not None:
        cfg.password_policy = _el_to_dict(pp_el)

    # ── Network Interfaces ────────────────────────────────────────────────────
    for iface in root.iter("Interface"):
        cfg.interfaces.append({
            "name":   _text(iface, "Name") or iface.get("Name", ""),
            "status": _text(iface, "Status", "Enable"),
            "zone":   _text(iface, "Zone"),
            "ipv4":   _text(iface, "IPAddress") or _text(iface, "IPv4Address"),
            "ipv6":   _text(iface, "IPv6Address") or _text(iface, "IPv6"),
            "type":   _text(iface, "Type") or iface.get("type", ""),
            "spoof_protection": _text(iface, "SpoofProtection") or _text(iface, "AntiSpoofing"),
            "mac":    _text(iface, "MACAddress"),
        })

    for zone in root.iter("Zone"):
        cfg.network_zones.append(_el_to_dict(zone))

    for r in root.iter("StaticRoute"):
        cfg.routing.append(_el_to_dict(r))

    # ── System Settings ───────────────────────────────────────────────────────
    sys_el = _first(root, ".//SystemSettings", ".//System", ".//BasicSettings")
    if sys_el is not None:
        cfg.system_settings = _el_to_dict(sys_el)

    for ntp in root.iter("NTPServer"):
        cfg.ntp_servers.append(_el_to_dict(ntp))
    # Some firmware stores NTP inline
    if not cfg.ntp_servers:
        ntp_el = _first(root, ".//NTP", ".//NTPSettings")
        if ntp_el is not None:
            cfg.ntp_servers = [_el_to_dict(ntp_el)]

    dns_el = _first(root, ".//DNSSettings", ".//DNS")
    if dns_el is not None:
        cfg.dns_settings = _el_to_dict(dns_el)

    snmp_el = _first(root, ".//SNMPSettings", ".//SNMP", ".//SNMPAgent")
    if snmp_el is not None:
        cfg.snmp_settings = _el_to_dict(snmp_el)

    ha_el = _first(root, ".//HASettings", ".//HighAvailability", ".//HA")
    if ha_el is not None:
        cfg.ha_settings = _el_to_dict(ha_el)

    backup_el = _first(root, ".//BackupSettings", ".//Backup", ".//AutomaticBackup")
    if backup_el is not None:
        cfg.backup_settings = _el_to_dict(backup_el)

    notif_el = _first(root, ".//NotificationSettings", ".//Notification", ".//AlertSettings")
    if notif_el is not None:
        cfg.notification_settings = _el_to_dict(notif_el)

    update_el = _first(root, ".//UpdateSettings", ".//PatternUpdate", ".//FirmwareUpdate",
                        ".//AutomaticUpdate")
    if update_el is not None:
        cfg.update_settings = _el_to_dict(update_el)

    # ── Security Services ─────────────────────────────────────────────────────
    for sl in root.iter("SyslogServer"):
        cfg.syslog_servers.append(_el_to_dict(sl))

    for cert in root.iter("Certificate"):
        cfg.certificates.append(_el_to_dict(cert))

    dos_el = _first(root, ".//DoSProtection", ".//DoSSettings")
    if dos_el is not None:
        cfg.dos_settings = _el_to_dict(dos_el)

    ips_el = _first(root, ".//IPSSettings", ".//IPS")
    if ips_el is not None:
        cfg.ips_settings = _el_to_dict(ips_el)

    for p in root.iter("IPSPolicy"):
        cfg.ips_policies.append(_el_to_dict(p))

    av_el = _first(root, ".//AntiVirusSettings", ".//AntiVirus", ".//MalwareProtection")
    if av_el is not None:
        cfg.av_settings = _el_to_dict(av_el)

    sandbox_el = _first(root, ".//SandstormSettings", ".//Sandstorm", ".//CloudSandbox")
    if sandbox_el is not None:
        cfg.sandbox_settings = _el_to_dict(sandbox_el)

    for wf in root.iter("WebFilterPolicy"):
        cfg.web_filter.append(_el_to_dict(wf))

    for ac in root.iter("ApplicationFilterPolicy"):
        cfg.app_control.append(_el_to_dict(ac))

    ssl_el = _first(root, ".//SSLInspection", ".//SSLTLSInspection", ".//HTTPSDecryption")
    if ssl_el is not None:
        cfg.ssl_inspection = _el_to_dict(ssl_el)

    email_el = _first(root, ".//EmailSettings", ".//SMTPSettings", ".//EmailProtection")
    if email_el is not None:
        cfg.email_settings = _el_to_dict(email_el)

    for svc in root.iter("Services"):
        cfg.services.append(_el_to_dict(svc))

    # ── Service definitions (port map) ────────────────────────────────────────
    # Capture individual <Service> elements that carry port information.
    # These are the named service objects (built-in + custom) referenced by rules.
    for svc in root.iter("Service"):
        name = _text(svc, "Name") or svc.get("name", "") or svc.get("Name", "")
        if not name:
            continue
        dst_port = _text(svc, "DestinationPort") or _text(svc, "DstPort") or _text(svc, "Port")
        src_port = _text(svc, "SourcePort") or _text(svc, "SrcPort")
        protocol = _text(svc, "Protocol") or _text(svc, "Type", "")
        if dst_port or protocol:
            cfg.service_defs[name] = {
                "dst_port": dst_port,
                "src_port": src_port,
                "protocol": protocol,
            }

    return cfg

"""Sophos XG/SFOS XML config parser."""
from lxml import etree
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SophosConfig:
    firewall_rules: list[dict] = field(default_factory=list)
    nat_rules: list[dict] = field(default_factory=list)
    vpn_ipsec: list[dict] = field(default_factory=list)
    vpn_ssl: list[dict] = field(default_factory=list)
    admin_settings: dict = field(default_factory=dict)
    device_access: list[dict] = field(default_factory=list)
    syslog_servers: list[dict] = field(default_factory=list)
    certificates: list[dict] = field(default_factory=list)
    dos_settings: dict = field(default_factory=dict)
    ips_settings: dict = field(default_factory=dict)
    web_filter: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    network_zones: list[dict] = field(default_factory=list)
    raw_sections: dict[str, int] = field(default_factory=dict)  # section tag -> count


def _text(el, tag: str, default: str = "") -> str:
    child = el.find(tag)
    return child.text.strip() if child is not None and child.text else default


def _children_text(el, tag: str) -> list[str]:
    return [c.text.strip() for c in el.findall(tag) if c.text]


def _el_to_dict(el) -> dict[str, Any]:
    """Shallow element to dict — text children only."""
    d: dict[str, Any] = {}
    for child in el:
        if len(child) == 0:
            d[child.tag] = child.text.strip() if child.text else ""
        else:
            # nested: collect as list or recurse
            existing = d.get(child.tag)
            item = _el_to_dict(child)
            if existing is None:
                d[child.tag] = item
            elif isinstance(existing, list):
                existing.append(item)
            else:
                d[child.tag] = [existing, item]
    return d


def parse(xml_bytes: bytes) -> SophosConfig:
    try:
        root = etree.fromstring(xml_bytes)
    except etree.XMLSyntaxError as exc:
        raise ValueError(f"Invalid XML: {exc}") from exc

    cfg = SophosConfig()

    # Record all top-level section tags for inventory
    for child in root:
        cfg.raw_sections[child.tag] = cfg.raw_sections.get(child.tag, 0) + 1

    # ── Firewall Rules ───────────────────────────────────────────────────────
    for rule in root.iter("FirewallRule"):
        cfg.firewall_rules.append({
            "name": _text(rule, "Name"),
            "status": _text(rule, "Status", "Enable"),
            "action": _text(rule, "NetworkPolicy/Action") or _text(rule, "Action"),
            "src_zones": _children_text(rule, "SourceZones/Zone") or _children_text(rule, "SourceZone"),
            "dst_zones": _children_text(rule, "DestinationZones/Zone") or _children_text(rule, "DestinationZone"),
            "src_networks": _children_text(rule, "SourceNetworks/Network") or _children_text(rule, "SourceNetwork"),
            "dst_networks": _children_text(rule, "DestinationNetworks/Network") or _children_text(rule, "DestinationNetwork"),
            "services": _children_text(rule, "Services/Service") or _children_text(rule, "Service"),
            "log_traffic": _text(rule, "LogTraffic", "Disable"),
            "schedule": _text(rule, "Schedule", "All the time"),
            "description": _text(rule, "Description"),
            "position": _text(rule, "Position"),
        })

    # ── NAT Rules ────────────────────────────────────────────────────────────
    for rule in root.iter("NATRule"):
        cfg.nat_rules.append(_el_to_dict(rule))

    # ── IPSec VPN ────────────────────────────────────────────────────────────
    for policy in root.iter("IPsecPolicy"):
        cfg.vpn_ipsec.append({
            "name": _text(policy, "Name"),
            "key_exchange": _text(policy, "KeyExchange"),
            "auth_mode": _text(policy, "AuthenticationMode"),
            "phase1_enc": _text(policy, "Phase1EncryptionAlgorithm") or _text(policy, "EncryptionAlgorithm"),
            "phase1_auth": _text(policy, "Phase1AuthenticationAlgorithm") or _text(policy, "AuthenticationAlgorithm"),
            "phase1_dh": _text(policy, "Phase1DHGroup") or _text(policy, "DHGroup"),
            "phase2_enc": _text(policy, "Phase2EncryptionAlgorithm"),
            "phase2_auth": _text(policy, "Phase2AuthenticationAlgorithm"),
            "phase2_pfs": _text(policy, "Phase2PFSGroup"),
            "lifetime": _text(policy, "KeyLife") or _text(policy, "Lifetime"),
        })

    # ── SSL VPN ──────────────────────────────────────────────────────────────
    for policy in root.iter("SSLVPNPolicy"):
        cfg.vpn_ssl.append(_el_to_dict(policy))

    # ── Admin / Device Access ────────────────────────────────────────────────
    admin_el = root.find(".//AdministrationSettings") or root.find(".//Administration")
    if admin_el is not None:
        cfg.admin_settings = _el_to_dict(admin_el)

    for da in root.iter("DeviceAccess"):
        cfg.device_access.append(_el_to_dict(da))

    # ── Syslog ───────────────────────────────────────────────────────────────
    for sl in root.iter("SyslogServer"):
        cfg.syslog_servers.append(_el_to_dict(sl))

    # ── Certificates ─────────────────────────────────────────────────────────
    for cert in root.iter("Certificate"):
        cfg.certificates.append(_el_to_dict(cert))

    # ── DoS ──────────────────────────────────────────────────────────────────
    dos_el = root.find(".//DoSProtection") or root.find(".//DoSSettings")
    if dos_el is not None:
        cfg.dos_settings = _el_to_dict(dos_el)

    # ── IPS ───────────────────────────────────────────────────────────────────
    ips_el = root.find(".//IPSSettings") or root.find(".//IPS")
    if ips_el is not None:
        cfg.ips_settings = _el_to_dict(ips_el)

    # ── Services ─────────────────────────────────────────────────────────────
    for svc in root.iter("Services"):
        cfg.services.append(_el_to_dict(svc))

    # ── Zones ────────────────────────────────────────────────────────────────
    for zone in root.iter("Zone"):
        cfg.network_zones.append(_el_to_dict(zone))

    return cfg

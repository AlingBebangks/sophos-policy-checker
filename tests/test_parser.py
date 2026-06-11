"""Parser unit tests — verify XML parsing correctness and security hardening."""
import pytest
from app.parser import parse


# ── Minimal valid config ──────────────────────────────────────────────────────

_MINIMAL = b"""<?xml version="1.0"?>
<Configuration>
  <FirewallRule>
    <Name>Test-Rule</Name>
    <Status>Enable</Status>
    <NetworkPolicy><Action>Accept</Action></NetworkPolicy>
    <SourceZones><Zone>LAN</Zone></SourceZones>
    <DestinationZones><Zone>WAN</Zone></DestinationZones>
    <LogTraffic>Enable</LogTraffic>
  </FirewallRule>
</Configuration>
"""


def test_parse_returns_sophos_config():
    cfg = parse(_MINIMAL)
    assert len(cfg.firewall_rules) == 1
    assert cfg.firewall_rules[0]["name"] == "Test-Rule"
    assert cfg.firewall_rules[0]["action"] == "Accept"


def test_parse_empty_xml():
    cfg = parse(b"<Configuration/>")
    assert cfg.firewall_rules == []
    assert cfg.nat_rules == []


def test_parse_invalid_xml_raises():
    with pytest.raises(ValueError, match="Invalid XML"):
        parse(b"this is not xml <<>>")


# ── XXE blocking ──────────────────────────────────────────────────────────────

def test_xxe_file_entity_blocked():
    """DOCTYPE with SYSTEM entity must not cause file-read or hang."""
    xxe = b"""<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<Configuration><x>&xxe;</x></Configuration>
"""
    # lxml with resolve_entities=False raises XMLSyntaxError on entity use
    with pytest.raises(ValueError):
        parse(xxe)


def test_xxe_billion_laughs_blocked():
    """Exponential entity expansion (billion laughs) must not consume memory."""
    bomb = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<Configuration>&lol3;</Configuration>
"""
    with pytest.raises(ValueError):
        parse(bomb)


# ── Firewall rule parsing ─────────────────────────────────────────────────────

_FW_RULES = b"""<?xml version="1.0"?>
<Configuration>
  <FirewallRule>
    <Name>WAN-to-DMZ</Name>
    <Status>Enable</Status>
    <NetworkPolicy><Action>Accept</Action></NetworkPolicy>
    <SourceZones><Zone>WAN</Zone></SourceZones>
    <DestinationZones><Zone>DMZ</Zone></DestinationZones>
    <LogTraffic>Disable</LogTraffic>
  </FirewallRule>
  <FirewallRule>
    <Name>Block-All</Name>
    <Status>Disable</Status>
    <NetworkPolicy><Action>Drop</Action></NetworkPolicy>
    <SourceZones><Zone>WAN</Zone></SourceZones>
    <DestinationZones><Zone>LAN</Zone></DestinationZones>
    <LogTraffic>Enable</LogTraffic>
  </FirewallRule>
</Configuration>
"""


def test_parse_multiple_firewall_rules():
    cfg = parse(_FW_RULES)
    assert len(cfg.firewall_rules) == 2
    names = [r["name"] for r in cfg.firewall_rules]
    assert "WAN-to-DMZ" in names
    assert "Block-All" in names


def test_parse_rule_disabled_status():
    cfg = parse(_FW_RULES)
    block = next(r for r in cfg.firewall_rules if r["name"] == "Block-All")
    assert block["status"].lower() in ("disable", "disabled")
    assert block["action"].lower() == "drop"


# ── NAT rule parsing ──────────────────────────────────────────────────────────

_NAT = b"""<?xml version="1.0"?>
<Configuration>
  <NATRule>
    <Name>RDP-Forward</Name>
    <Type>DNAT</Type>
    <OriginalPort>3389</OriginalPort>
    <TranslatedDestination>192.168.1.10</TranslatedDestination>
  </NATRule>
</Configuration>
"""


def test_parse_nat_rule():
    cfg = parse(_NAT)
    assert len(cfg.nat_rules) == 1
    assert cfg.nat_rules[0]["Name"] == "RDP-Forward"


# ── IPSec VPN parsing ─────────────────────────────────────────────────────────

_IPSEC = b"""<?xml version="1.0"?>
<Configuration>
  <IPsecPolicy>
    <Name>Site-A</Name>
    <KeyExchange>IKEv2</KeyExchange>
    <Phase1EncryptionAlgorithm>DES</Phase1EncryptionAlgorithm>
    <Phase1AuthenticationAlgorithm>MD5</Phase1AuthenticationAlgorithm>
    <Phase1DHGroup>2</Phase1DHGroup>
    <AuthenticationMode>PSK</AuthenticationMode>
    <KeyLife>172800</KeyLife>
  </IPsecPolicy>
</Configuration>
"""


def test_parse_ipsec_policy():
    cfg = parse(_IPSEC)
    assert len(cfg.vpn_ipsec) == 1
    p = cfg.vpn_ipsec[0]
    assert p["name"] == "Site-A"
    assert p["phase1_enc"].upper() == "DES"
    assert p["phase1_auth"].upper() == "MD5"
    assert p["phase1_dh"] == "2"
    assert p["auth_mode"].upper() == "PSK"


# ── PPTP parsing ──────────────────────────────────────────────────────────────

_PPTP = b"""<?xml version="1.0"?>
<Configuration>
  <PPTPSettings>
    <Status>Enable</Status>
    <IPRange>10.10.10.1-10.10.10.50</IPRange>
  </PPTPSettings>
</Configuration>
"""


def test_parse_pptp_settings():
    cfg = parse(_PPTP)
    assert cfg.vpn_pptp != {}
    assert cfg.vpn_pptp.get("Status", "").lower() == "enable"


# ── Service definition parsing ────────────────────────────────────────────────
# Sophos XG stores named service objects inside a <Services> container. The
# parser uses root.iter("Service") so it finds them at any depth — but the
# test must reflect the real backup structure to catch depth-related regressions.

_SERVICES = b"""<?xml version="1.0"?>
<Configuration>
  <Services>
    <Service>
      <Name>Custom-Telnet</Name>
      <DestinationPort>23</DestinationPort>
      <Protocol>TCP</Protocol>
    </Service>
    <Service>
      <Name>Custom-MySQL</Name>
      <DestinationPort>3306</DestinationPort>
      <Protocol>TCP</Protocol>
    </Service>
  </Services>
</Configuration>
"""


def test_parse_service_definitions():
    cfg = parse(_SERVICES)
    assert "Custom-Telnet" in cfg.service_defs, "Custom-Telnet not in service_defs"
    assert cfg.service_defs["Custom-Telnet"]["dst_port"] == "23"
    assert cfg.service_defs["Custom-Telnet"]["protocol"] == "TCP"
    assert "Custom-MySQL" in cfg.service_defs
    assert cfg.service_defs["Custom-MySQL"]["dst_port"] == "3306"


def test_service_refs_in_rules_not_added_to_defs():
    """Service name-reference nodes inside rules must not pollute service_defs."""
    xml = b"""<?xml version="1.0"?>
<Configuration>
  <FirewallRule>
    <Name>Rule1</Name>
    <Services>
      <Service>HTTP</Service>
      <Service>HTTPS</Service>
    </Services>
  </FirewallRule>
</Configuration>
"""
    cfg = parse(xml)
    # "HTTP" and "HTTPS" are text references, not service definition objects
    # — they have no <Name> child so must not appear in service_defs
    assert "HTTP" not in cfg.service_defs
    assert "HTTPS" not in cfg.service_defs

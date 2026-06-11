"""Check module unit tests — verify findings are produced for known-bad configs."""
import pytest
from app.parser import parse
from app.engine import run_all
from app.checks.models import Severity


def _findings_of(xml: bytes, *, title_contains: str = "", severity: Severity | None = None,
                 category: str = "") -> list:
    cfg = parse(xml)
    findings = run_all(cfg)
    result = findings
    if title_contains:
        result = [f for f in result if title_contains.lower() in f.title.lower()]
    if severity:
        result = [f for f in result if f.severity == severity]
    if category:
        result = [f for f in result if f.category == category]
    return result


# ── Firewall checks ───────────────────────────────────────────────────────────

def test_any_any_rule_detected():
    xml = b"""<Configuration>
      <FirewallRule>
        <Name>Permissive</Name>
        <Status>Enable</Status>
        <NetworkPolicy><Action>Accept</Action></NetworkPolicy>
        <SourceZones><Zone>LAN</Zone></SourceZones>
        <DestinationZones><Zone>WAN</Zone></DestinationZones>
        <LogTraffic>Enable</LogTraffic>
      </FirewallRule>
    </Configuration>"""
    hits = _findings_of(xml, title_contains="Any-to-Any")
    # No src/dst networks defined = any-to-any
    assert len(hits) == 1
    assert hits[0].severity == Severity.CRITICAL


def test_wan_zone_any_source_detected():
    xml = b"""<Configuration>
      <FirewallRule>
        <Name>WAN-Open</Name>
        <Status>Enable</Status>
        <NetworkPolicy><Action>Accept</Action></NetworkPolicy>
        <SourceZones><Zone>WAN</Zone></SourceZones>
        <DestinationZones><Zone>DMZ</Zone></DestinationZones>
        <LogTraffic>Enable</LogTraffic>
      </FirewallRule>
    </Configuration>"""
    hits = _findings_of(xml, title_contains="WAN-zone accept")
    assert len(hits) == 1
    assert hits[0].severity == Severity.HIGH


def test_disabled_drop_rule_flagged_high():
    xml = b"""<Configuration>
      <FirewallRule>
        <Name>Block-Mgmt</Name>
        <Status>Disable</Status>
        <NetworkPolicy><Action>Drop</Action></NetworkPolicy>
        <SourceZones><Zone>WAN</Zone></SourceZones>
        <DestinationZones><Zone>LAN</Zone></DestinationZones>
        <LogTraffic>Enable</LogTraffic>
      </FirewallRule>
    </Configuration>"""
    hits = _findings_of(xml, title_contains="disabled drop", severity=Severity.HIGH)
    assert len(hits) == 1


def test_pii_in_rule_name_detected():
    xml = b"""<Configuration>
      <FirewallRule>
        <Name>Juan Reyes VPN Access</Name>
        <Status>Enable</Status>
        <NetworkPolicy><Action>Accept</Action></NetworkPolicy>
        <LogTraffic>Enable</LogTraffic>
      </FirewallRule>
    </Configuration>"""
    hits = _findings_of(xml, title_contains="personal names")
    assert len(hits) == 1


# ── VPN checks ────────────────────────────────────────────────────────────────

def test_pptp_enabled_flagged_critical():
    xml = b"""<Configuration>
      <PPTPSettings><Status>Enable</Status></PPTPSettings>
    </Configuration>"""
    hits = _findings_of(xml, title_contains="PPTP", severity=Severity.CRITICAL)
    assert len(hits) == 1


def test_weak_ipsec_encryption_detected():
    xml = b"""<Configuration>
      <IPsecPolicy>
        <Name>Weak</Name>
        <Phase1EncryptionAlgorithm>DES</Phase1EncryptionAlgorithm>
        <Phase1AuthenticationAlgorithm>SHA256</Phase1AuthenticationAlgorithm>
        <Phase1DHGroup>14</Phase1DHGroup>
      </IPsecPolicy>
    </Configuration>"""
    hits = _findings_of(xml, title_contains="Weak encryption", severity=Severity.CRITICAL)
    assert len(hits) == 1
    assert any("DES" in a for a in hits[0].affected)


def test_ssl_vpn_broad_scope_detected():
    xml = b"""<Configuration>
      <SSLVPNPolicy>
        <Name>All-Staff</Name>
        <DestinationNetworks>Any</DestinationNetworks>
      </SSLVPNPolicy>
    </Configuration>"""
    hits = _findings_of(xml, title_contains="SSL VPN policies grant access to all")
    assert len(hits) == 1
    assert hits[0].severity == Severity.HIGH


# ── NAT checks ───────────────────────────────────────────────────────────────

def test_rdp_dnat_flagged_critical():
    xml = b"""<Configuration>
      <NATRule>
        <Name>RDP-FWD</Name>
        <Type>DNAT</Type>
        <TranslatedPort>3389</TranslatedPort>
        <TranslatedDestination>192.168.1.5</TranslatedDestination>
        <OriginalSource>Any</OriginalSource>
      </NATRule>
    </Configuration>"""
    hits = _findings_of(xml, title_contains="RDP", severity=Severity.CRITICAL)
    assert len(hits) == 1


def test_dnat_any_source_flagged():
    xml = b"""<Configuration>
      <NATRule>
        <Name>Web-Forward</Name>
        <Type>DNAT</Type>
        <TranslatedDestination>10.0.0.10</TranslatedDestination>
        <OriginalSource>Any</OriginalSource>
      </NATRule>
    </Configuration>"""
    hits = _findings_of(xml, title_contains="unrestricted source")
    assert len(hits) == 1


# ── Framework reference enrichment ───────────────────────────────────────────

def test_nist_references_added_to_firewall_findings():
    xml = b"""<Configuration>
      <FirewallRule>
        <Name>Open</Name>
        <Status>Enable</Status>
        <NetworkPolicy><Action>Accept</Action></NetworkPolicy>
        <LogTraffic>Enable</LogTraffic>
      </FirewallRule>
    </Configuration>"""
    cfg = parse(xml)
    findings = run_all(cfg)
    fw_findings = [f for f in findings if f.category == "Firewall Rules"]
    for f in fw_findings:
        nist_refs = [r for r in f.references if "NIST SP 800-53" in r]
        assert len(nist_refs) > 0, f"No NIST SP 800-53 refs in finding: {f.title}"
        cis_refs = [r for r in f.references if "CIS Controls" in r]
        assert len(cis_refs) > 0, f"No CIS Controls refs in finding: {f.title}"

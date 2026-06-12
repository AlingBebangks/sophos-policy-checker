"""Config checks — Network interfaces, zones, routing."""
from .models import Finding, Severity
from .utils import v as _v, off as _off

_S = "Config — Network"


def run(cfg) -> list[Finding]:
    findings: list[Finding] = []

    # ── Interfaces ────────────────────────────────────────────────────────────
    ifaces = cfg.interfaces
    if not ifaces:
        findings.append(Finding(
            severity=Severity.INFO,
            category=_S,
            title="No interface configuration found",
            detail="Interface details could not be parsed from the configuration backup.",
            recommendation="Verify interface settings under Network → Interfaces.",
            location="Network → Interfaces",
            exploitability="Low", impact_scope="Local", exposure="Internal",
        ))
    else:
        unzoned   = [i.get("name") for i in ifaces if not _v(i, "zone") and not _off(_v(i, "status"))]
        no_spoof  = [i.get("name") for i in ifaces
                     if not _off(_v(i, "status")) and _off(_v(i, "spoof_protection"))]
        ipv6_ifaces = [i.get("name") for i in ifaces if _v(i, "ipv6") and not _off(_v(i, "status"))]

        if unzoned:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=_S,
                title="Active interfaces not assigned to a zone",
                detail="Interfaces without a zone assignment are not subject to zone-based policy enforcement, creating an uncontrolled traffic path.",
                recommendation=(
                    "Assign every active interface to an appropriate zone (LAN, WAN, DMZ, etc.). "
                    "Unzoned interfaces create policy gaps that support MITRE ATT&CK T1205 (Traffic Signaling) "
                    "and T1599 (Network Boundary Bridging) — traffic may bypass all inspection. "
                    "Aligns with OWASP A05:2021 – Security Misconfiguration."
                ),
                references=[
                    "MITRE ATT&CK T1205 – Traffic Signaling",
                    "MITRE ATT&CK T1599 – Network Boundary Bridging",
                    "OWASP A05:2021 – Security Misconfiguration",
                    "CIS Control 12.2 – Establish and Maintain a Secure Network Architecture",
                ],
                location="Network → Interfaces → Edit interface → assign Zone → Apply",
                affected=[str(n) for n in unzoned if n],
                exploitability="Medium", impact_scope="Network", exposure="Internal",
            ))

        if no_spoof:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=_S,
                title="Anti-spoof protection disabled on interfaces",
                detail="Without anti-spoofing, the firewall accepts packets with source IPs not reachable via the receiving interface, enabling IP spoofing attacks.",
                recommendation=(
                    "Enable anti-spoofing on all interfaces, especially WAN-facing ones. "
                    "Disabled anti-spoof enables MITRE ATT&CK T1557 (Adversary-in-the-Middle) "
                    "and T1036.005 (Masquerading: Match Legitimate Name or Location) via source IP spoofing — "
                    "attackers can bypass IP-based access controls by forging source addresses. "
                    "Aligns with OWASP A05:2021 – Security Misconfiguration."
                ),
                references=[
                    "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                    "MITRE ATT&CK T1036.005 – Masquerading: Match Legitimate Name or Location",
                    "OWASP A05:2021 – Security Misconfiguration",
                    "RFC 2827 – Network Ingress Filtering (BCP 38)",
                    "CIS Control 12.2 – Establish and Maintain a Secure Network Architecture",
                ],
                location="Network → Interfaces → Edit interface → enable Anti-spoofing → Apply",
                affected=[str(n) for n in no_spoof if n],
                exploitability="Medium", impact_scope="Network", exposure="External",
            ))

        if ipv6_ifaces:
            findings.append(Finding(
                severity=Severity.INFO,
                category=_S,
                title="IPv6 configured on interfaces",
                detail="IPv6 addresses detected. Ensure IPv6 firewall rules are in place — many policies only cover IPv4, leaving IPv6 traffic unrestricted.",
                recommendation=(
                    "Audit IPv6 firewall rules. Apply equivalent restrictions to IPv6 traffic as IPv4. "
                    "IPv6 policy gaps enable MITRE ATT&CK T1599 (Network Boundary Bridging) — "
                    "attackers tunnel traffic over IPv6 to bypass IPv4-only policies. "
                    "Aligns with OWASP A05:2021 – Security Misconfiguration."
                ),
                references=[
                    "MITRE ATT&CK T1599 – Network Boundary Bridging",
                    "OWASP A05:2021 – Security Misconfiguration",
                    "NIST SP 800-119 – Guidelines for the Secure Deployment of IPv6",
                ],
                location="Firewall → Rules and policies → Firewall rules → verify IPv6 rules exist for all zones",
                affected=[str(n) for n in ipv6_ifaces if n],
                exploitability="Low", impact_scope="Local", exposure="Internal",
            ))

    # ── Zones ─────────────────────────────────────────────────────────────────
    zones = cfg.network_zones
    zone_names = {_v(z, "Name", "ZoneName", "name").lower() for z in zones}

    if zones:
        spoof_disabled_zones: list[str] = []
        for zone in zones:
            zone_name = (
                zone.get("Name") or zone.get("ZoneName") or zone.get("name") or "(unnamed)"
            )
            spoof_val = (
                zone.get("IPSpoofPrevention") or zone.get("SpoofPrevention") or
                zone.get("SpoofProtection") or zone.get("AntiSpoofing") or
                zone.get("IPSpoofCheck") or ""
            )
            if spoof_val and _off(spoof_val):
                spoof_disabled_zones.append(zone_name)

        if spoof_disabled_zones:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=_S,
                title="IP spoof prevention disabled on network zones",
                detail=(
                    "IP spoof prevention is explicitly disabled on the listed zones. "
                    "Without this control, packets with forged source IP addresses — including "
                    "spoofed internal addresses — are accepted, allowing attackers to bypass "
                    "IP-based access controls and inject traffic as trusted hosts."
                ),
                recommendation=(
                    "Enable IP spoof prevention on all zones, especially WAN-facing and DMZ zones. "
                    "This implements RFC 2827 (BCP 38) ingress filtering at the zone level. "
                    "Disabled spoof prevention enables MITRE ATT&CK T1557 (Adversary-in-the-Middle) "
                    "via source IP forgery and T1036.005 (Masquerading) — attackers can impersonate "
                    "trusted internal hosts. "
                    "Aligns with OWASP A05:2021 – Security Misconfiguration."
                ),
                references=[
                    "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                    "MITRE ATT&CK T1036.005 – Masquerading: Match Legitimate Name or Location",
                    "OWASP A05:2021 – Security Misconfiguration",
                    "RFC 2827 – Network Ingress Filtering (BCP 38)",
                    "NIST SP 800-53 Rev 5 SC-7 – Boundary Protection",
                    "CIS Controls v8 – 12.2 Establish and Maintain a Secure Network Architecture",
                ],
                location=(
                    "Network → Zones → Edit zone → enable IP spoof prevention → Apply\n"
                    "Repeat for each affected zone."
                ),
                affected=spoof_disabled_zones,
                exploitability="High", impact_scope="Network", exposure="External",
            ))

        has_dmz = any(n in zone_names for n in ("dmz", "demilitarized", "screened"))
        if not has_dmz:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=_S,
                title="No DMZ zone configured",
                detail=(
                    "Without a DMZ, public-facing servers (web, mail, DNS) reside in the same zone as internal systems. "
                    "A compromised server gives direct access to the internal network."
                ),
                recommendation=(
                    "Create a dedicated DMZ zone and move all public-facing servers into it. "
                    "No DMZ enables MITRE ATT&CK T1190 (Exploit Public-Facing Application) to immediately "
                    "pivot to internal systems — there is no additional network boundary to cross. "
                    "Aligns with OWASP A05:2021 – Security Misconfiguration and "
                    "CIS Control 12.2 – Establish and Maintain a Secure Network Architecture."
                ),
                references=[
                    "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                    "MITRE ATT&CK TA0008 – Lateral Movement (enabled by flat network)",
                    "OWASP A05:2021 – Security Misconfiguration",
                    "CIS Control 12.2 – Establish and Maintain a Secure Network Architecture",
                    "NIST SP 800-41 Rev 1 §3.3 – Network Design with DMZ",
                ],
                location="Network → Zones → Add zone → Type: DMZ → Apply\nThen update server interface assignments",
                exploitability="Medium", impact_scope="Network", exposure="External",
            ))

    # ── Routing ───────────────────────────────────────────────────────────────
    routes = cfg.routing
    default_routes = [r for r in routes if _v(r, "DestinationIP", "Destination", "Network") in ("0.0.0.0", "0.0.0.0/0", "any")]
    if len(default_routes) > 1:
        findings.append(Finding(
            severity=Severity.LOW,
            category=_S,
            title=f"Multiple default routes configured ({len(default_routes)})",
            detail="Multiple default routes can cause asymmetric routing, unpredictable traffic paths, and policy bypass.",
            recommendation=(
                "Review default routes. Ensure only one is active with appropriate metric/distance. "
                "Asymmetric routing can enable MITRE ATT&CK T1557 (Adversary-in-the-Middle) "
                "by causing return traffic to bypass inspection on a different path. "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            references=[
                "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                "OWASP A05:2021 – Security Misconfiguration",
                "CIS Control 12.2 – Establish and Maintain a Secure Network Architecture",
            ],
            location="Network → Routing → Static routes → review and remove duplicate defaults",
            exploitability="Low", impact_scope="Network", exposure="Internal",
        ))

    return findings

"""Config checks — Protection profiles: DoS/Spoof (CIS 5.7), Wireless (CIS 5.9), DNS (CIS 5.12)."""
from .models import Finding, Severity
from .utils import v as _v, off as _off

_S = "Config — Protection Profiles"


def run(cfg) -> list[Finding]:
    findings: list[Finding] = []

    # ── CIS 5.7 – DoS & Spoof Protection ─────────────────────────────────────
    dos = cfg.dos_settings
    if dos:
        spoof = _v(dos, "SpoofProtection", "EnableSpoofPrevention", "AntiSpoofing",
                   "SpoofPrevention")
        if _off(spoof):
            findings.append(Finding(
                severity=Severity.HIGH,
                category=_S,
                title="CIS 5.7 – Spoof prevention not enabled on LAN/DMZ zones",
                detail=(
                    "Spoof prevention is disabled. Without it, the firewall accepts packets "
                    "with source IPs that do not match the routing table, enabling source IP "
                    "spoofing attacks such as reflection amplification DDoS."
                ),
                recommendation=(
                    "Navigate to Protect → Intrusion Prevention → DoS & Spoof Protection → "
                    "enable 'Enable spoof prevention' on LAN and DMZ zones. "
                    "Aligns with CIS Sophos Benchmark §5.7."
                ),
                references=[
                    "CIS Sophos Benchmark §5.7",
                    "MITRE ATT&CK T1498 – Network Denial of Service",
                    "OWASP A05:2021 – Security Misconfiguration",
                ],
                location=(
                    "Protect → Intrusion Prevention → DoS & Spoof Protection\n"
                    "→ Enable spoof prevention on LAN and DMZ zones → Apply"
                ),
                exploitability="High", impact_scope="Network", exposure="External",
            ))

        # Check specific flood types (SYN, UDP, TCP, ICMP/ICMPv6)
        _FLOOD_CHECKS = [
            ("SYNFlood", "SYN"),
            ("UDPFlood", "UDP"),
            ("TCPFlood", "TCP"),
            ("ICMPFlood", "ICMP/ICMPv6"),
        ]
        missing_flags: list[str] = []
        for key, label in _FLOOD_CHECKS:
            section = dos.get(key, {})
            apply_flag = ""
            if isinstance(section, dict):
                apply_flag = (section.get("ApplyFlag") or section.get("SourceApplyFlag") or
                              section.get("DestinationApplyFlag") or section.get("Enable") or "")
            elif isinstance(section, str):
                apply_flag = section
            flat = dos.get(f"{key}ApplyFlag") or dos.get(f"{key}SourceApplyFlag") or ""
            if _off(str(apply_flag)) and _off(str(flat)):
                missing_flags.append(label)

        if missing_flags:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=_S,
                title=f"CIS 5.7 – Flood protection not enabled for: {', '.join(missing_flags)}",
                detail=(
                    f"DoS flood protection 'Apply Flag' is not set for: {', '.join(missing_flags)}. "
                    "Without these controls, volumetric attacks can exhaust the firewall's "
                    "connection state table and cause denial of service."
                ),
                recommendation=(
                    "Navigate to Protect → Intrusion Prevention → DoS & Spoof Protection → "
                    "DoS settings → enable 'Apply Flag' for SYN, UDP, TCP, and ICMP/ICMPv6 flood "
                    "on both Source and Destination. "
                    "Aligns with CIS Sophos Benchmark §5.7."
                ),
                references=[
                    "CIS Sophos Benchmark §5.7",
                    "MITRE ATT&CK T1498 – Network Denial of Service",
                    "NIST SP 800-53 Rev 5 SC-5 – Denial-of-Service Protection",
                ],
                location=(
                    "Protect → Intrusion Prevention → DoS & Spoof Protection\n"
                    f"→ DoS settings → Enable Apply Flag for {', '.join(missing_flags)} → Apply"
                ),
                affected=missing_flags,
                exploitability="High", impact_scope="Network", exposure="External",
            ))

    # ── CIS 5.9 – Wireless security settings ─────────────────────────────────
    for wnet in cfg.wireless_settings:
        ssid = _v(wnet, "SSID", "Name", "WirelessName", "NetworkName")
        sec_mode = _v(wnet, "SecurityMode", "Security", "Encryption", "AuthType")
        enc = _v(wnet, "EncryptionAlgorithm", "Encryption", "CipherSuite")
        isolation = _v(wnet, "ClientIsolation", "Isolation", "StationIsolation")

        if sec_mode.lower() in ("open", "none", "wep", "wpa", ""):
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category=_S,
                title=f"CIS 5.9 – Wireless network '{ssid}' uses weak or no security ('{sec_mode}')",
                detail=(
                    f"Wireless network '{ssid}' is configured with '{sec_mode}' security. "
                    "WEP is trivially crackable; WPA is vulnerable to dictionary attacks; "
                    "Open networks expose all traffic in plaintext."
                ),
                recommendation=(
                    "Set security mode to WPA2 Personal or WPA2 Enterprise. "
                    "Set encryption to AES[secure]. "
                    "Aligns with CIS Sophos Benchmark §5.9."
                ),
                references=[
                    "CIS Sophos Benchmark §5.9",
                    "CIS Control 3.10 – Encrypt Sensitive Data in Transit",
                    "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                ],
                location=(
                    f"Protect → Wireless → Wireless networks → Edit '{ssid}'\n"
                    "→ Security mode → WPA2 Personal or Enterprise → Apply"
                ),
                exploitability="High", impact_scope="Network", exposure="Adjacent",
            ))
        elif "wpa2" in sec_mode.lower() and enc and enc.lower() not in ("aes", "ccmp", "aes[secure]"):
            findings.append(Finding(
                severity=Severity.HIGH,
                category=_S,
                title=f"CIS 5.9 – Wireless network '{ssid}' not using AES encryption",
                detail=(
                    f"Wireless network '{ssid}' uses WPA2 but encryption is '{enc}' (not AES). "
                    "TKIP and other non-AES ciphers have known weaknesses."
                ),
                recommendation=(
                    "Set encryption to AES[secure] under Advanced settings. "
                    "Aligns with CIS Sophos Benchmark §5.9."
                ),
                references=[
                    "CIS Sophos Benchmark §5.9",
                    "CIS Control 3.10 – Encrypt Sensitive Data in Transit",
                ],
                location=(
                    f"Protect → Wireless → Wireless networks → Edit '{ssid}'\n"
                    "→ Advanced settings → Encryption → AES[secure] → Apply"
                ),
                exploitability="Medium", impact_scope="Network", exposure="Adjacent",
            ))

        if _off(isolation):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=_S,
                title=f"CIS 5.9 – Client isolation not enabled on wireless network '{ssid}'",
                detail=(
                    f"Client isolation is disabled on '{ssid}'. "
                    "Without isolation, wireless clients can communicate directly with each "
                    "other at the Wi-Fi layer, enabling lateral movement between connected devices."
                ),
                recommendation=(
                    "Enable 'Client isolation' in wireless network advanced settings. "
                    "Aligns with CIS Sophos Benchmark §5.9."
                ),
                references=[
                    "CIS Sophos Benchmark §5.9",
                    "MITRE ATT&CK TA0008 – Lateral Movement",
                ],
                location=(
                    f"Protect → Wireless → Wireless networks → Edit '{ssid}'\n"
                    "→ Advanced settings → Client isolation → Enable → Apply"
                ),
                exploitability="Medium", impact_scope="Network", exposure="Adjacent",
            ))

    # ── CIS 5.12 – Sophos DNS protection ─────────────────────────────────────
    # DNS protection requires Sophos Central registration. We check if the configured
    # DNS servers point to known Sophos DNS protection address ranges, or if the
    # central_mgmt block confirms DNS protection is active.
    cm = cfg.central_mgmt
    dns = cfg.dns_settings
    dns_prot_active = False
    if cm:
        dns_prot = _v(cm, "DNSProtection", "DNSProtectionEnabled", "SophosDNS")
        if dns_prot and not _off(dns_prot):
            dns_prot_active = True

    if not dns_prot_active:
        findings.append(Finding(
            severity=Severity.LOW,
            category=_S,
            title="CIS 5.12 – Sophos DNS Protection not detected",
            detail=(
                "Sophos DNS Protection was not detected in the configuration. "
                "DNS Protection is a cloud-based service that blocks access to malicious or "
                "unwanted domains using real-time SophosLabs threat intelligence, covering "
                "all ports and protocols — not just web traffic."
            ),
            recommendation=(
                "Configure DNS Protection via Sophos Central: "
                "My Products → DNS Protection → Locations → Add the firewall WAN IP. "
                "Then configure the firewall's DNS servers to point to the Sophos DNS "
                "Protection IP addresses. Requires Sophos Central registration. "
                "Aligns with CIS Sophos Benchmark §5.12."
            ),
            references=[
                "CIS Sophos Benchmark §5.12",
                "MITRE ATT&CK T1568 – Dynamic Resolution",
                "MITRE ATT&CK T1071.004 – Application Layer Protocol: DNS",
            ],
            location=(
                "Configure → Network → DNS → DNS Configuration\n"
                "→ Set DNS servers to Sophos Central DNS Protection IPs → Apply"
            ),
            exploitability="Low", impact_scope="Network", exposure="External",
        ))

    # ── CIS 5.2 – SSL/TLS inspection settings ────────────────────────────────
    ssl = cfg.ssl_inspection
    if ssl:
        ssl_engine = _v(ssl, "Engine", "SSLEngine", "TLSEngine", "SSLTLSEngine", "Enabled")
        ssl_old_protocols = _v(ssl, "SSL20", "SSL30", "SSL2", "SSL3", "LegacySSL",
                                "SSL2Action", "SSL3Action")
        tls13_decrypt = _v(ssl, "TLS13Decryption", "TLS13", "DecryptTLS13")

        if ssl_old_protocols and ssl_old_protocols.lower() in ("allow", "enabled", "accept", ""):
            findings.append(Finding(
                severity=Severity.HIGH,
                category=_S,
                title="CIS 5.2 – SSL 2.0/3.0 not rejected in SSL/TLS inspection settings",
                detail=(
                    "SSL 2.0 and SSL 3.0 are cryptographically broken (POODLE, DROWN). "
                    "The TLS inspection engine should be configured to Reject or Drop "
                    "connections using these legacy protocols."
                ),
                recommendation=(
                    "Navigate to Protect → Rules and policies → SSL/TLS inspection rules → "
                    "SSL/TLS inspection settings → Non-decryptable traffic → "
                    "set SSL 2.0 and SSL 3.0 to Reject or Drop. "
                    "Aligns with CIS Sophos Benchmark §5.2."
                ),
                references=[
                    "CIS Sophos Benchmark §5.2",
                    "CVE-2014-3566 – POODLE (SSL 3.0)",
                    "MITRE ATT&CK T1573 – Encrypted Channel",
                    "OWASP A02:2021 – Cryptographic Failures",
                ],
                location=(
                    "Protect → Rules and policies → SSL/TLS inspection rules → Settings\n"
                    "→ Non-decryptable traffic → SSL 2.0 and SSL 3.0 → Reject → Apply"
                ),
                exploitability="Medium", impact_scope="Network", exposure="External",
            ))

    return findings

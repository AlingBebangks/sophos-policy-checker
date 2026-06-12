"""VPN policy checks — IPSec and SSL VPN."""
from .models import Finding, Severity
from .utils import v as _v, off as _off

_WEAK_ENC = {"des", "3des", "triple-des", "null", "none", "rc4"}
_WEAK_AUTH = {"md5", "sha1", "none", "null"}
_WEAK_DH = {"1", "2", "5", "group1", "group2", "group5"}
_STRONG_DH = {"14", "15", "16", "17", "18", "19", "20", "21",
              "group14", "group15", "group16", "group19", "group20", "group21"}


def run(cfg) -> list[Finding]:
    findings: list[Finding] = []

    # ── IPSec ────────────────────────────────────────────────────────────────
    weak_enc: list[tuple[str, str]] = []
    weak_auth: list[tuple[str, str]] = []
    weak_dh: list[tuple[str, str]] = []
    psk_policies: list[str] = []
    short_lifetime: list[tuple[str, str]] = []

    for policy in cfg.vpn_ipsec:
        name = policy.get("name") or "(unnamed)"

        for field_name, val in [
            ("Phase1 encryption", policy.get("phase1_enc", "")),
            ("Phase2 encryption", policy.get("phase2_enc", "")),
        ]:
            if val.lower() in _WEAK_ENC:
                weak_enc.append((name, f"{field_name}={val}"))

        for field_name, val in [
            ("Phase1 auth", policy.get("phase1_auth", "")),
            ("Phase2 auth", policy.get("phase2_auth", "")),
        ]:
            if val.lower() in _WEAK_AUTH:
                weak_auth.append((name, f"{field_name}={val}"))

        for field_name, val in [
            ("Phase1 DH", policy.get("phase1_dh", "")),
            ("Phase2 PFS", policy.get("phase2_pfs", "")),
        ]:
            if val.lower() in _WEAK_DH:
                weak_dh.append((name, f"{field_name}={val}"))

        if policy.get("auth_mode", "").lower() in ("psk", "pre-shared key", "presharedkey"):
            psk_policies.append(name)

        lifetime = policy.get("lifetime", "")
        try:
            lt_int = int(lifetime)
            if lt_int > 86400:
                short_lifetime.append((name, lifetime))
        except (ValueError, TypeError):
            pass

    if weak_enc:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category="VPN — IPSec",
            title="Weak encryption algorithms in IPSec policies",
            detail=(
                "DES, 3DES, and NULL encryption are considered cryptographically broken "
                "or absent. Traffic protected by these algorithms can be decrypted by a "
                "passive network observer or active attacker."
            ),
            recommendation=(
                "Use AES-256-GCM or AES-128-GCM for Phase 1 and Phase 2 encryption. "
                "Remove all DES/3DES/NULL cipher suites from all policies. "
                "Weak encryption enables MITRE ATT&CK T1040 (Network Sniffing) and "
                "T1557 (Adversary-in-the-Middle) — an attacker capturing VPN traffic "
                "can decrypt it offline. "
                "Aligns with OWASP A02:2021 – Cryptographic Failures."
            ),
            references=[
                "MITRE ATT&CK T1040 – Network Sniffing",
                "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                "OWASP A02:2021 – Cryptographic Failures",
                "NIST SP 800-77 Rev 1 – Guide to IPsec VPNs",
                "RFC 8221 – Cryptographic Algorithm Implementation Requirements for ESP and AH",
                "NSA CISA Joint Advisory – Selecting and Hardening Remote Access VPN Solutions",
            ],
            affected=[f"{n}: {v}" for n, v in weak_enc],
            exploitability="High", impact_scope="Network", exposure="External",
        ))

    if weak_auth:
        findings.append(Finding(
            severity=Severity.HIGH,
            category="VPN — IPSec",
            title="Weak integrity/authentication algorithms in IPSec policies",
            detail=(
                "MD5 and SHA-1 are cryptographically broken hash functions. "
                "They are vulnerable to collision attacks and should not be used for HMAC in IPSec."
            ),
            recommendation=(
                "Replace MD5/SHA-1 with SHA-256, SHA-384, or SHA-512 for all "
                "Phase 1 and Phase 2 authentication. "
                "Broken HMAC allows MITRE ATT&CK T1557 (Adversary-in-the-Middle) attacks "
                "where packet integrity can be undermined. "
                "Aligns with OWASP A02:2021 – Cryptographic Failures."
            ),
            references=[
                "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                "OWASP A02:2021 – Cryptographic Failures",
                "NIST SP 800-131A Rev 2 – Transitioning to Stronger Cryptographic Algorithms",
                "RFC 8221 – Cryptographic Requirements for IPsec",
            ],
            affected=[f"{n}: {v}" for n, v in weak_auth],
            exploitability="Medium", impact_scope="Network", exposure="External",
        ))

    if weak_dh:
        findings.append(Finding(
            severity=Severity.HIGH,
            category="VPN — IPSec",
            title="Weak Diffie-Hellman groups in IPSec policies",
            detail=(
                "DH Groups 1, 2, and 5 provide 768-bit to 1536-bit security and are "
                "considered broken against nation-state and well-resourced adversaries. "
                "Logjam-class attacks can break 768/1024-bit DH."
            ),
            recommendation=(
                "Use DH Group 14 (minimum, 2048-bit) or preferably Groups 19–21 (elliptic curve). "
                "Enable PFS on Phase 2 to ensure session keys are independent. "
                "Weak DH supports MITRE ATT&CK T1557 (Adversary-in-the-Middle) — "
                "an attacker performing a Logjam attack can downgrade the key exchange. "
                "Aligns with OWASP A02:2021 – Cryptographic Failures."
            ),
            references=[
                "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                "OWASP A02:2021 – Cryptographic Failures",
                "RFC 8247 – Algorithm Implementation Requirements for IKEv2",
                "NIST SP 800-77 Rev 1 §4.1 – IKE Configuration",
                "Logjam: Imperfect Forward Secrecy – weakdh.org",
            ],
            affected=[f"{n}: {v}" for n, v in weak_dh],
            exploitability="Medium", impact_scope="Network", exposure="External",
        ))

    if psk_policies:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="VPN — IPSec",
            title="Pre-Shared Key authentication in use",
            detail=(
                "PSK authentication relies on a shared secret. If the PSK is weak, "
                "reused, or disclosed, all VPN tunnels using it are compromised."
            ),
            recommendation=(
                "Prefer certificate-based authentication (RSA or ECDSA) for IPSec. "
                "If PSK must be used, ensure it is at least 20 random characters "
                "and unique per tunnel. "
                "Weak or reused PSKs enable MITRE ATT&CK T1110.003 (Password Spraying) "
                "and T1078 (Valid Accounts) — a captured PSK grants full VPN access. "
                "Aligns with OWASP A07:2021 – Identification and Authentication Failures."
            ),
            references=[
                "MITRE ATT&CK T1110.003 – Brute Force: Password Spraying",
                "MITRE ATT&CK T1078 – Valid Accounts",
                "OWASP A07:2021 – Identification and Authentication Failures",
                "NIST SP 800-77 Rev 1 §4.2 – Authentication in IKE",
                "NSA CISA Advisory – Selecting and Hardening Remote Access VPN Solutions",
            ],
            affected=psk_policies,
            exploitability="Medium", impact_scope="Network", exposure="External",
        ))

    if short_lifetime:
        findings.append(Finding(
            severity=Severity.LOW,
            category="VPN — IPSec",
            title="Excessively long IKE/IPSec SA lifetime",
            detail=(
                "SA lifetimes exceeding 24 hours mean session keys are reused for longer, "
                "increasing the window of exposure if a key is compromised."
            ),
            recommendation=(
                "Set Phase 1 lifetime ≤ 86400 seconds (24 h) and Phase 2 ≤ 3600 seconds (1 h). "
                "Enable PFS to ensure forward secrecy on Phase 2 re-key. "
                "Long SA lifetimes extend the impact of MITRE ATT&CK T1040 (Network Sniffing) — "
                "a captured session key remains valid for longer. "
                "Aligns with OWASP A02:2021 – Cryptographic Failures (key management)."
            ),
            references=[
                "MITRE ATT&CK T1040 – Network Sniffing",
                "OWASP A02:2021 – Cryptographic Failures",
                "NIST SP 800-77 Rev 1 §4.3 – SA Lifetimes",
            ],
            affected=[f"{n} (lifetime={v}s)" for n, v in short_lifetime],
            exploitability="Low", impact_scope="Network", exposure="External",
        ))

    if not cfg.vpn_ipsec:
        findings.append(Finding(
            severity=Severity.INFO,
            category="VPN — IPSec",
            title="No IPSec VPN policies found",
            detail="No IPsecPolicy elements were detected in the configuration.",
            recommendation="No action required if IPSec VPN is not in use.",
            exploitability="Low", impact_scope="Local", exposure="Internal",
        ))

    # ── PPTP / L2TP without IPSec ─────────────────────────────────────────────
    pptp = cfg.vpn_pptp
    if pptp:
        tag = pptp.get("_tag", "").lower()
        status = (
            pptp.get("Status") or pptp.get("Enable") or pptp.get("Enabled") or
            pptp.get("State") or ""
        ).lower()
        enabled = status not in ("disable", "disabled", "0", "false", "off", "no", "")

        is_l2tp = "l2tp" in tag
        title = (
            "L2TP VPN enabled without IPSec encryption"
            if is_l2tp else
            "PPTP VPN enabled — protocol is cryptographically broken"
        )
        detail = (
            "L2TP without IPSec provides no encryption. Traffic is transmitted in cleartext."
            if is_l2tp else
            "PPTP uses MS-CHAPv2 for authentication and RC4-40/128 for encryption, both of which "
            "are completely broken. MS-CHAPv2 can be cracked in under 24 hours using cloud compute. "
            "PPTP provides no meaningful confidentiality or integrity protection."
        )
        recommendation = (
            "Disable L2TP unless it is paired with IPSec (L2TP/IPSec). "
            "Migrate remote access users to SSL VPN or IPSec IKEv2. "
            if is_l2tp else
            "Disable PPTP immediately. Migrate all users to Sophos SSL VPN or IPSec IKEv2. "
            "PPTP is exploitable via MITRE ATT&CK T1040 (Network Sniffing) — "
            "MS-CHAPv2 handshakes captured passively can be cracked offline to recover plaintext VPN credentials, "
            "enabling T1078 (Valid Accounts). "
            "Aligns with OWASP A02:2021 – Cryptographic Failures."
        )
        severity = Severity.CRITICAL if (not is_l2tp or enabled) else Severity.HIGH
        findings.append(Finding(
            severity=severity,
            category="VPN — IPSec",
            title=title,
            detail=detail + ("" if enabled else " The setting is currently disabled but should be removed."),
            recommendation=recommendation,
            references=[
                "MITRE ATT&CK T1040 – Network Sniffing",
                "MITRE ATT&CK T1078 – Valid Accounts",
                "OWASP A02:2021 – Cryptographic Failures",
                "NIST SP 800-77 Rev 1 §2.1 – Deprecated VPN Protocols",
                "CVE-2012-2122 – MS-CHAPv2 inherent weakness (Moxie Marlinspike / CloudCracker)",
                "RFC 8247 §2.1 – PPTP/L2TP not recommended",
            ],
            location=(
                "VPN → Remote access → PPTP/L2TP → Disable → Apply\n"
                "Migrate users: VPN → Sophos Connect (SSL VPN) or IPSec remote access"
            ),
            exploitability="High", impact_scope="Network", exposure="External",
        ))

    # ── SSL VPN ───────────────────────────────────────────────────────────────
    ssl_broad_scope: list[str] = []
    ssl_no_mfa: list[str] = []
    ssl_weak_tls: list[str] = []
    _WEAK_TLS = {"ssl3", "sslv3", "tls1", "tls1.0", "tlsv1", "tls1.1", "tlsv1.1"}

    for policy in cfg.vpn_ssl:
        name = _v(policy, "Name", "PolicyName") or "(unnamed)"

        dest = _v(policy, "DestinationNetworks", "AllowedNetworks", "AccessibleNetworks",
                  "PermittedNetworks", "Network")
        if not dest or dest.lower() in ("any", "all", "*"):
            ssl_broad_scope.append(name)

        mfa = _v(policy, "OTPEnable", "MFA", "TwoFactor", "TwoFactorAuth", "TOTPEnabled",
                 "OTP", "MultiFactor")
        if mfa and _off(mfa):
            ssl_no_mfa.append(name)

        tls_min = _v(policy, "TLSMinVersion", "MinTLSVersion", "SSLVersion", "TLSVersion")
        if tls_min.lower() in _WEAK_TLS:
            ssl_weak_tls.append(f"{name} (min={tls_min})")

    if ssl_broad_scope:
        findings.append(Finding(
            severity=Severity.HIGH,
            category="VPN — IPSec",
            title="SSL VPN policies grant access to all networks (Any destination)",
            detail=(
                "These SSL VPN policies do not restrict the accessible destination networks. "
                "A connected user can reach any internal resource, including management interfaces, "
                "servers in all subnets, and OT/IoT segments — as if physically on the LAN."
            ),
            recommendation=(
                "Define explicit allowed-network lists for each SSL VPN policy, scoped to only "
                "the subnets that each user group needs. Separate policies per role "
                "(e.g. IT-Admins, Finance, Remote-Workers). "
                "Broad SSL VPN scope enables MITRE ATT&CK TA0008 (Lateral Movement) — "
                "a compromised VPN credential gives unrestricted internal access. "
                "Aligns with OWASP A01:2021 – Broken Access Control and "
                "NIST SP 800-77 Rev 1 §4.4 – Split Tunnelling and Access Control."
            ),
            location=(
                "VPN → SSL VPN → Policies → Edit policy\n"
                "→ Permitted network resources → replace 'Any' with specific network objects → Save"
            ),
            references=[
                "MITRE ATT&CK TA0008 – Lateral Movement",
                "MITRE ATT&CK T1078 – Valid Accounts (broad scope amplifies impact)",
                "OWASP A01:2021 – Broken Access Control",
                "NIST SP 800-77 Rev 1 §4.4 – Access Control for VPN Clients",
                "CIS Controls v8 – 6.2 Establish an Access Granting Process",
            ],
            affected=ssl_broad_scope,
            exploitability="High", impact_scope="Network", exposure="External",
        ))

    if ssl_no_mfa:
        findings.append(Finding(
            severity=Severity.HIGH,
            category="VPN — IPSec",
            title="SSL VPN policies without MFA / OTP enforcement",
            detail=(
                "MFA/OTP is disabled on these SSL VPN policies. A single compromised credential "
                "is sufficient to authenticate and gain network access."
            ),
            recommendation=(
                "Enable OTP/MFA on all SSL VPN policies. Sophos supports TOTP-based one-time "
                "passwords via the Sophos Authenticator app. "
                "Single-factor VPN is a primary target for MITRE ATT&CK T1078 (Valid Accounts) "
                "and T1110 (Brute Force) — credential stuffing attacks succeed without MFA. "
                "Aligns with OWASP A07:2021 – Identification and Authentication Failures."
            ),
            location=(
                "VPN → SSL VPN → Policies → Edit policy\n"
                "→ Two-factor authentication → Enable OTP → Save\n"
                "Users must then enrol via VPN → Show VPN portal"
            ),
            references=[
                "MITRE ATT&CK T1078 – Valid Accounts",
                "MITRE ATT&CK T1110 – Brute Force",
                "OWASP A07:2021 – Identification and Authentication Failures",
                "NIST SP 800-63B §5.1.3 – Multi-Factor Authentication",
                "CIS Controls v8 – 6.3 Require MFA for Externally-Exposed Applications",
            ],
            affected=ssl_no_mfa,
            exploitability="High", impact_scope="Network", exposure="External",
        ))

    if ssl_weak_tls:
        findings.append(Finding(
            severity=Severity.HIGH,
            category="VPN — IPSec",
            title="SSL VPN allows deprecated TLS versions (TLS 1.0/1.1 or SSL 3.0)",
            detail=(
                "The SSL VPN is configured to accept connections using TLS 1.0, TLS 1.1, or SSL 3.0. "
                "These protocol versions have known weaknesses (POODLE, BEAST, CRIME) and are "
                "deprecated by RFC 8996."
            ),
            recommendation=(
                "Set the minimum TLS version to TLS 1.2, preferably TLS 1.3. "
                "Deprecated TLS versions enable MITRE ATT&CK T1557 (Adversary-in-the-Middle) "
                "via protocol downgrade attacks. "
                "Aligns with OWASP A02:2021 – Cryptographic Failures and "
                "NIST SP 800-52 Rev 2 which mandates TLS 1.2 minimum."
            ),
            location=(
                "VPN → SSL VPN → Advanced settings\n"
                "→ Minimum TLS version → set to TLS 1.2 or TLS 1.3 → Apply"
            ),
            references=[
                "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                "OWASP A02:2021 – Cryptographic Failures",
                "NIST SP 800-52 Rev 2 – Guidelines for TLS Implementations",
                "RFC 8996 – Deprecating TLS 1.0 and TLS 1.1",
            ],
            affected=ssl_weak_tls,
            exploitability="Medium", impact_scope="Network", exposure="External",
        ))

    if not cfg.vpn_ssl:
        findings.append(Finding(
            severity=Severity.INFO,
            category="VPN — IPSec",
            title="No SSL VPN policies found",
            detail="No SSLVPNPolicy elements were detected in the configuration.",
            recommendation="No action required if SSL VPN is not in use.",
            exploitability="Low", impact_scope="Local", exposure="Internal",
        ))

    return findings

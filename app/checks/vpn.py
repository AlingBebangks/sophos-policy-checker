"""VPN policy checks — IPSec and SSL VPN."""
from .models import Finding, Severity

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
            if lt_int > 86400:  # > 24 hours
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
                "or absent. Traffic protected by these algorithms can be decrypted."
            ),
            recommendation=(
                "Use AES-256-GCM or AES-128-GCM for Phase 1 and Phase 2 encryption. "
                "Remove all DES/3DES/NULL cipher suites."
            ),
            references=["NIST SP 800-77 Rev 1", "RFC 8221"],
            affected=[f"{n}: {v}" for n, v in weak_enc],
        ))

    if weak_auth:
        findings.append(Finding(
            severity=Severity.HIGH,
            category="VPN — IPSec",
            title="Weak integrity/authentication algorithms in IPSec policies",
            detail=(
                "MD5 and SHA-1 are cryptographically broken hash functions. "
                "They are vulnerable to collision attacks and should not be used for HMAC."
            ),
            recommendation=(
                "Replace MD5/SHA-1 with SHA-256, SHA-384, or SHA-512 for all "
                "Phase 1 and Phase 2 authentication."
            ),
            references=["NIST SP 800-131A Rev 2"],
            affected=[f"{n}: {v}" for n, v in weak_auth],
        ))

    if weak_dh:
        findings.append(Finding(
            severity=Severity.HIGH,
            category="VPN — IPSec",
            title="Weak Diffie-Hellman groups in IPSec policies",
            detail=(
                "DH Groups 1, 2, and 5 provide 768-bit to 1536-bit security and are "
                "considered broken against nation-state and well-resourced adversaries."
            ),
            recommendation=(
                "Use DH Group 14 (minimum) or preferably Groups 19–21 (elliptic curve). "
                "Enable PFS on Phase 2."
            ),
            references=["RFC 8247", "NIST SP 800-77 Rev 1 §4.1"],
            affected=[f"{n}: {v}" for n, v in weak_dh],
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
                "and unique per tunnel."
            ),
            affected=psk_policies,
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
                "Enable PFS to ensure forward secrecy on Phase 2 re-key."
            ),
            affected=[f"{n} (lifetime={v}s)" for n, v in short_lifetime],
        ))

    if not cfg.vpn_ipsec:
        findings.append(Finding(
            severity=Severity.INFO,
            category="VPN — IPSec",
            title="No IPSec VPN policies found",
            detail="No IPsecPolicy elements were detected in the configuration.",
            recommendation="No action required if IPSec VPN is not in use.",
        ))

    return findings

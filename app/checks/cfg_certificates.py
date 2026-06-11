"""Config checks — Certificate hygiene (self-signed, expiry, weak algorithms)."""
from __future__ import annotations
from datetime import datetime, timezone
from .models import Finding, Severity

_S = "Config — Certificates"
_WEAK_SIG = {"sha1", "sha1withrsa", "md5", "md5withrsa", "md2"}
_WARN_DAYS = 90
_CRIT_DAYS = 30


from .utils import v as _v


def _days_until(date_str: str) -> int | None:
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%Y/%m/%d", "%b %d %H:%M:%S %Y GMT",
                "%Y-%m-%dT%H:%M:%S", "%d-%m-%Y"):
        try:
            expiry = datetime.strptime(date_str.strip(), fmt).replace(tzinfo=timezone.utc)
            return (expiry - datetime.now(timezone.utc)).days
        except ValueError:
            continue
    return None


def run(cfg) -> list[Finding]:
    findings: list[Finding] = []
    certs = cfg.certificates

    if not certs:
        findings.append(Finding(
            severity=Severity.INFO,
            category=_S,
            title="No certificates found in config",
            detail="No Certificate elements were detected. The device may be using the default self-signed certificate.",
            recommendation="Review certificate configuration under System → Certificates.",
            location="System → Certificates → review installed certificates",
        ))
        return findings

    self_signed:   list[str] = []
    expiring_warn: list[str] = []
    expiring_crit: list[str] = []
    expired:       list[str] = []
    weak_sig:      list[str] = []
    small_key:     list[str] = []

    for cert in certs:
        name      = _v(cert, "Name", "CertificateName", "CommonName")
        ca        = _v(cert, "CertificateAuthority", "CA", "IsCA", "SelfSigned",
                       "IsSelfSigned", "Type")
        expiry    = _v(cert, "ValidTo", "ExpiryDate", "NotAfter", "Expiry")
        sig_alg   = _v(cert, "SignatureAlgorithm", "Algorithm", "HashAlgorithm")
        key_len   = _v(cert, "KeyLength", "KeySize", "BitLength")
        cert_type = _v(cert, "CertificateType", "Type", "Usage")

        label = name or "(unnamed)"

        if ca.lower() in ("selfsigned", "self-signed", "self_signed", "yes", "true", "1") \
                or cert_type.lower() in ("selfsigned", "self-signed"):
            self_signed.append(label)

        if expiry:
            days = _days_until(expiry)
            if days is not None:
                if days < 0:
                    expired.append(f"{label} (expired {abs(days)} days ago)")
                elif days <= _CRIT_DAYS:
                    expiring_crit.append(f"{label} (expires in {days} days)")
                elif days <= _WARN_DAYS:
                    expiring_warn.append(f"{label} (expires in {days} days)")

        if sig_alg and sig_alg.lower().replace("-", "").replace(" ", "") in _WEAK_SIG:
            weak_sig.append(f"{label} ({sig_alg})")

        try:
            if key_len and int(key_len) < 2048:
                small_key.append(f"{label} ({key_len} bit)")
        except (ValueError, TypeError):
            pass

    if expired:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category=_S,
            title="Expired certificates installed",
            detail="Expired certificates cause TLS handshake failures, browser warnings, and can block VPN or management access.",
            recommendation=(
                "Replace expired certificates immediately with valid, CA-signed certificates. "
                "Expired certs are also exploited in MITRE ATT&CK T1557 (Adversary-in-the-Middle) "
                "— clients ignoring cert errors accept fraudulent certs from attackers. "
                "Aligns with OWASP A02:2021 – Cryptographic Failures."
            ),
            references=[
                "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                "OWASP A02:2021 – Cryptographic Failures",
                "CIS Control 4.1 – Establish and Maintain a Secure Configuration Process",
            ],
            location="System → Certificates → find expired cert → Upload/Replace → Apply",
            affected=expired,
        ))

    if expiring_crit:
        findings.append(Finding(
            severity=Severity.HIGH,
            category=_S,
            title=f"Certificates expiring within {_CRIT_DAYS} days",
            detail=f"These certificates expire within {_CRIT_DAYS} days. Failure to renew will break dependent services.",
            recommendation=(
                "Renew or replace these certificates before expiry. "
                "Imminent expiry enables MITRE ATT&CK T1557 (Adversary-in-the-Middle) — "
                "users trained to click through cert errors become easy MitM targets. "
                "Aligns with OWASP A02:2021 – Cryptographic Failures."
            ),
            references=[
                "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                "OWASP A02:2021 – Cryptographic Failures",
            ],
            location="System → Certificates → select cert → Renew/Replace → Apply",
            affected=expiring_crit,
        ))

    if expiring_warn:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title=f"Certificates expiring within {_WARN_DAYS} days",
            detail=f"These certificates will expire within {_WARN_DAYS} days. Plan renewal now.",
            recommendation="Schedule certificate renewal within the next 30 days.",
            references=[
                "OWASP A02:2021 – Cryptographic Failures",
                "CIS Control 4.1 – Establish and Maintain a Secure Configuration Process",
            ],
            location="System → Certificates → select cert → Renew → Apply",
            affected=expiring_warn,
        ))

    if self_signed:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="Self-signed certificates in use",
            detail=(
                "Self-signed certificates are not trusted by clients or browsers and cannot be "
                "validated against a certificate authority. They are also commonly used in MitM attacks."
            ),
            recommendation=(
                "Replace self-signed certificates with certificates issued by a trusted internal CA "
                "or a public CA (Let's Encrypt, DigiCert, etc.) for any user-facing or external service. "
                "Self-signed certs are routinely accepted in MITRE ATT&CK T1557 (Adversary-in-the-Middle) attacks — "
                "users can't distinguish your self-signed cert from an attacker's. "
                "Aligns with OWASP A02:2021 – Cryptographic Failures."
            ),
            references=[
                "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                "OWASP A02:2021 – Cryptographic Failures",
                "CA/Browser Forum Baseline Requirements",
            ],
            location="System → Certificates → Upload a CA-signed certificate → bind it to the relevant service → Apply",
            affected=self_signed,
        ))

    if weak_sig:
        findings.append(Finding(
            severity=Severity.HIGH,
            category=_S,
            title="Certificates using weak signature algorithms (SHA-1 / MD5)",
            detail="SHA-1 and MD5 are cryptographically broken. Certificates signed with these algorithms are vulnerable to collision attacks enabling certificate forgery.",
            recommendation=(
                "Replace all SHA-1/MD5 certificates with SHA-256 or stronger. "
                "Weak signature certs enable MITRE ATT&CK T1553.004 (Subvert Trust Controls: Install Root Certificate) "
                "— a forged collision cert can be installed as trusted. "
                "Aligns with OWASP A02:2021 – Cryptographic Failures."
            ),
            references=[
                "MITRE ATT&CK T1553.004 – Subvert Trust Controls: Install Root Certificate",
                "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                "OWASP A02:2021 – Cryptographic Failures",
                "NIST SP 800-131A Rev 2 – Transitioning Away from SHA-1",
                "CA/Browser Forum Baseline Requirements §7.1.3",
            ],
            location="System → Certificates → replace cert → upload SHA-256 signed certificate → Apply",
            affected=weak_sig,
        ))

    if small_key:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="Certificates with RSA key size below 2048 bits",
            detail="RSA keys smaller than 2048 bits are considered weak and can be factored with sufficient computing resources.",
            recommendation=(
                "Replace all sub-2048-bit certificates with 2048-bit (minimum) or 4096-bit RSA, or use ECDSA P-256/P-384. "
                "Small RSA keys enable MITRE ATT&CK T1557 (Adversary-in-the-Middle) via certificate forgery. "
                "Aligns with OWASP A02:2021 – Cryptographic Failures."
            ),
            references=[
                "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                "OWASP A02:2021 – Cryptographic Failures",
                "NIST SP 800-57 Part 1 Rev 5 – Key Management",
                "CA/Browser Forum Baseline Requirements §6.1.5",
            ],
            location="System → Certificates → replace cert → generate 2048+ bit key → Apply",
            affected=small_key,
        ))

    return findings

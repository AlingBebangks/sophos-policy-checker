"""Config checks — Email protection and SMTP relay security."""
from .models import Finding, Severity
from .utils import v as _v, off as _off

_S = "Config — Email & SMTP"


def run(cfg) -> list[Finding]:
    findings: list[Finding] = []
    email = cfg.email_settings

    if not email:
        findings.append(Finding(
            severity=Severity.INFO,
            category=_S,
            title="Email/SMTP settings not found",
            detail="No email configuration was detected. If SMTP relay or email protection is in use, verify settings manually.",
            recommendation="Review email protection under Email → General settings.",
            location="Email → General settings",
        ))
        return findings

    # ── TLS enforcement ───────────────────────────────────────────────────────
    tls = _v(email, "TLSEnabled", "TLS", "SMTPTLSEnabled", "TLSEncryption", "SecureTransport")
    if _off(tls):
        findings.append(Finding(
            severity=Severity.HIGH,
            category=_S,
            title="SMTP TLS encryption not enforced",
            detail="Email relayed without TLS is transmitted in cleartext, exposing message content and credentials to interception.",
            recommendation=(
                "Enable TLS for all inbound and outbound SMTP connections. Configure opportunistic TLS minimum (TLS 1.2+). "
                "Cleartext SMTP enables MITRE ATT&CK T1040 (Network Sniffing) and "
                "T1557 (Adversary-in-the-Middle) — email credentials and content are visible on the wire. "
                "Aligns with OWASP A02:2021 – Cryptographic Failures."
            ),
            references=[
                "MITRE ATT&CK T1040 – Network Sniffing",
                "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                "OWASP A02:2021 – Cryptographic Failures",
                "RFC 8314 – Use of TLS for Email Submission and Access",
                "NIST SP 800-177 Rev 1 – Trustworthy Email",
            ],
            location="Email → SMTP → TLS settings → Enable TLS → set minimum TLS 1.2 → Apply",
        ))

    # ── SPF / DKIM / DMARC ───────────────────────────────────────────────────
    spf   = _v(email, "SPF", "SPFCheck", "SPFVerification", "EnableSPF")
    dkim  = _v(email, "DKIM", "DKIMCheck", "DKIMVerification", "EnableDKIM")
    dmarc = _v(email, "DMARC", "DMARCCheck", "EnableDMARC")

    if _off(spf):
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="SPF (Sender Policy Framework) checking disabled",
            detail="Without SPF verification, spoofed sender addresses pass undetected, enabling phishing and spam relay.",
            recommendation=(
                "Enable SPF checking to reject email from unauthorised sending hosts. "
                "Disabled SPF enables MITRE ATT&CK T1566.001 (Spearphishing Attachment) and "
                "T1036 (Masquerading) — attackers spoof your domain to deliver targeted phishing. "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            references=[
                "MITRE ATT&CK T1566.001 – Phishing: Spearphishing Attachment",
                "MITRE ATT&CK T1036 – Masquerading",
                "OWASP A05:2021 – Security Misconfiguration",
                "RFC 7208 – Sender Policy Framework (SPF)",
                "NIST SP 800-177 Rev 1 §4.6",
            ],
            location="Email → Antispam → SPF → Enable SPF check → Apply",
        ))

    if _off(dkim):
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="DKIM (DomainKeys Identified Mail) checking disabled",
            detail="Without DKIM verification, tampered or spoofed email cannot be cryptographically detected.",
            recommendation=(
                "Enable DKIM verification for inbound email. "
                "Disabled DKIM enables MITRE ATT&CK T1566 (Phishing) — "
                "message tampering and domain spoofing cannot be detected cryptographically. "
                "Aligns with OWASP A02:2021 – Cryptographic Failures."
            ),
            references=[
                "MITRE ATT&CK T1566 – Phishing",
                "OWASP A02:2021 – Cryptographic Failures",
                "RFC 6376 – DomainKeys Identified Mail (DKIM) Signatures",
                "NIST SP 800-177 Rev 1 §4.5",
            ],
            location="Email → Antispam → DKIM → Enable DKIM check → Apply",
        ))

    if _off(dmarc):
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="DMARC checking disabled",
            detail="DMARC combines SPF and DKIM to enforce domain-level email policy. Without it, spoofing protections are incomplete.",
            recommendation=(
                "Enable DMARC checking and configure reject or quarantine policy. "
                "Without DMARC, MITRE ATT&CK T1566.001 (Spearphishing Attachment) using spoofed domains "
                "succeeds even when SPF and DKIM are present but misaligned. "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            references=[
                "MITRE ATT&CK T1566.001 – Phishing: Spearphishing Attachment",
                "MITRE ATT&CK T1036 – Masquerading",
                "OWASP A05:2021 – Security Misconfiguration",
                "RFC 7489 – Domain-based Message Authentication (DMARC)",
                "NIST SP 800-177 Rev 1 §4.7",
            ],
            location="Email → Antispam → DMARC → Enable DMARC check → Apply",
        ))

    # ── Antispam ──────────────────────────────────────────────────────────────
    spam = _v(email, "AntiSpam", "SpamCheck", "SpamEnabled", "AntiSpamEnabled")
    if _off(spam):
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="Antispam scanning disabled",
            detail="Spam filtering disabled means users receive all spam, including phishing emails with malicious links.",
            recommendation=(
                "Enable antispam scanning for all inbound SMTP connections. "
                "Disabled antispam enables MITRE ATT&CK T1566 (Phishing) at scale — "
                "mass phishing campaigns reach every inbox without gateway filtering. "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            references=[
                "MITRE ATT&CK T1566 – Phishing",
                "MITRE ATT&CK T1566.002 – Phishing: Spearphishing Link",
                "OWASP A05:2021 – Security Misconfiguration",
                "CIS Control 9.6 – Block Unnecessary File Types",
            ],
            location="Email → Antispam → Enable antispam → Apply",
        ))

    # ── Open relay ────────────────────────────────────────────────────────────
    relay = _v(email, "RelayRestriction", "OpenRelay", "AllowRelay", "AuthRequired")
    if relay.lower() in ("all", "any", "allow", "") and not _off(relay):
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category=_S,
            title="SMTP relay may be configured as open relay",
            detail="An open relay allows any sender to use the firewall to send email to any destination, enabling spam abuse and IP blacklisting.",
            recommendation=(
                "Restrict SMTP relay to authenticated senders or specific internal IP ranges only. "
                "An open relay enables MITRE ATT&CK T1566 (Phishing) at massive scale — "
                "attackers relay spam/phishing through your IP, causing blacklisting. "
                "Also enables T1036 (Masquerading) by relaying spoofed-sender mail. "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            references=[
                "MITRE ATT&CK T1566 – Phishing",
                "MITRE ATT&CK T1036 – Masquerading",
                "OWASP A05:2021 – Security Misconfiguration",
                "RFC 5321 §7.5 – Open Mail Relays (explicitly deprecated)",
                "NIST SP 800-177 Rev 1 §4.1 – Preventing Open Relays",
            ],
            location="Email → SMTP → Relay settings → restrict to authenticated users or internal networks only → Apply",
        ))

    return findings

"""Config checks — Email protection and SMTP relay security."""
from .models import Finding, Severity

_S = "Config — Email & SMTP"


def _v(d: dict, *keys: str) -> str:
    for k in keys:
        v = d.get(k, "")
        if v:
            return str(v).strip()
    return ""


def _off(val: str) -> bool:
    return val.lower() in ("disable", "disabled", "0", "false", "off", "no", "")


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
            recommendation="Enable TLS for all inbound and outbound SMTP connections. Configure opportunistic TLS minimum.",
            location="Email → SMTP → TLS settings → Enable TLS → set minimum TLS 1.2 → Apply",
            references=["RFC 8314", "NIST SP 800-177"],
        ))

    # ── SPF / DKIM / DMARC ───────────────────────────────────────────────────
    spf  = _v(email, "SPF", "SPFCheck", "SPFVerification", "EnableSPF")
    dkim = _v(email, "DKIM", "DKIMCheck", "DKIMVerification", "EnableDKIM")
    dmarc = _v(email, "DMARC", "DMARCCheck", "EnableDMARC")

    if _off(spf):
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="SPF (Sender Policy Framework) checking disabled",
            detail="Without SPF verification, spoofed sender addresses pass undetected, enabling phishing and spam relay.",
            recommendation="Enable SPF checking to reject email from unauthorised sending hosts.",
            location="Email → Antispam → SPF → Enable SPF check → Apply",
        ))

    if _off(dkim):
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="DKIM (DomainKeys Identified Mail) checking disabled",
            detail="Without DKIM verification, tampered or spoofed email cannot be cryptographically detected.",
            recommendation="Enable DKIM verification for inbound email.",
            location="Email → Antispam → DKIM → Enable DKIM check → Apply",
        ))

    if _off(dmarc):
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="DMARC checking disabled",
            detail="DMARC combines SPF and DKIM to enforce domain-level email policy. Without it, spoofing protections are weaker.",
            recommendation="Enable DMARC checking and configure reject or quarantine policy.",
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
            recommendation="Enable antispam scanning for all inbound SMTP connections.",
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
            recommendation="Restrict SMTP relay to authenticated senders or specific internal IP ranges only.",
            location="Email → SMTP → Relay settings → restrict to authenticated users or internal networks only → Apply",
        ))

    return findings

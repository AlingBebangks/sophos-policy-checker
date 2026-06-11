"""Administration and device access checks."""
from .models import Finding, Severity
from .utils import v as _val, off as _off

_ADMIN_NAV = "Administration → Device access"
_ADMIN_SETTINGS_NAV = "Administration → Admin and user settings"


def run(cfg) -> list[Finding]:
    findings: list[Finding] = []
    admin = cfg.admin_settings

    # ── HTTP management ───────────────────────────────────────────────────────
    http_port_raw = _val(admin, "HTTPPort", "WebAdminHTTP")
    if http_port_raw and http_port_raw not in ("0", "false", "disable", ""):
        findings.append(Finding(
            severity=Severity.HIGH,
            category="Administration",
            title="HTTP (cleartext) management access enabled",
            detail=(
                "The management interface is accessible over plain HTTP. "
                "Administrator credentials and session tokens are transmitted in cleartext."
            ),
            recommendation=(
                "Disable HTTP management access and enforce HTTPS-only with a valid certificate. "
                "HTTP management directly enables MITRE ATT&CK T1040 (Network Sniffing) and "
                "T1557 (Adversary-in-the-Middle) — credentials can be captured from the wire. "
                "Aligns with OWASP A02:2021 – Cryptographic Failures and "
                "A07:2021 – Identification and Authentication Failures."
            ),
            references=[
                "MITRE ATT&CK T1040 – Network Sniffing",
                "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                "OWASP A02:2021 – Cryptographic Failures",
                "OWASP A07:2021 – Identification and Authentication Failures",
                "CIS Control 4.6 – Securely Manage Enterprise Assets and Software Remotely",
                "CIS Sophos Benchmark §1.1",
            ],
            location=(
                f"{_ADMIN_NAV}\n"
                "→ Find the zone row → uncheck 'HTTP' under the Admin column → Apply"
            ),
        ))

    # ── Session timeout ───────────────────────────────────────────────────────
    timeout = _val(admin, "SessionTimeout", "IdleTimeout", "AdminTimeout")
    try:
        timeout_int = int(timeout)
        if timeout_int == 0:
            findings.append(Finding(
                severity=Severity.HIGH,
                category="Administration",
                title="Admin session timeout disabled (set to 0)",
                detail="A session timeout of 0 means admin sessions never expire automatically.",
                recommendation=(
                    "Set the admin session timeout to 15 minutes or less. "
                    "Persistent sessions enable MITRE ATT&CK T1078 (Valid Accounts) — "
                    "an unattended console or hijacked session token remains valid indefinitely. "
                    "Aligns with OWASP A07:2021 – Identification and Authentication Failures."
                ),
                references=[
                    "MITRE ATT&CK T1078 – Valid Accounts",
                    "OWASP A07:2021 – Identification and Authentication Failures",
                    "CIS Control 5.3 – Disable Dormant Accounts",
                ],
                location=(
                    f"{_ADMIN_SETTINGS_NAV}\n"
                    "→ Scroll to 'Login security' → set 'Logout session after' to 15 minutes → Apply"
                ),
            ))
        elif timeout_int > 30:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category="Administration",
                title=f"Admin session timeout is long ({timeout_int} minutes)",
                detail=(
                    f"The admin session timeout is set to {timeout_int} minutes. "
                    "Long timeouts leave unattended sessions exposed."
                ),
                recommendation=(
                    "Reduce admin session timeout to 15 minutes or less. "
                    "Long timeouts extend the exploitation window for "
                    "MITRE ATT&CK T1078 (Valid Accounts) and session hijacking. "
                    "Aligns with OWASP A07:2021 – Identification and Authentication Failures."
                ),
                references=[
                    "MITRE ATT&CK T1078 – Valid Accounts",
                    "OWASP A07:2021 – Identification and Authentication Failures",
                    "CIS Control 5.3 – Disable Dormant Accounts",
                ],
                location=(
                    f"{_ADMIN_SETTINGS_NAV}\n"
                    "→ Scroll to 'Login security' → reduce 'Logout session after' to 15 minutes → Apply"
                ),
            ))
    except (ValueError, TypeError):
        pass

    # ── Password complexity ───────────────────────────────────────────────────
    complexity = _val(admin, "PasswordComplexity", "AdminPasswordComplexity")
    if _off(complexity):
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="Administration",
            title="Admin password complexity enforcement not detected",
            detail=(
                "Password complexity enforcement was not found or is disabled. "
                "Weak admin passwords are a leading cause of firewall compromise."
            ),
            recommendation=(
                "Enable password complexity: minimum 12 characters with upper/lowercase, "
                "numbers, and special characters. "
                "Weak passwords directly enable MITRE ATT&CK T1110.001 (Password Guessing) "
                "and T1110.003 (Password Spraying) against the management interface. "
                "Aligns with OWASP A07:2021 – Identification and Authentication Failures."
            ),
            references=[
                "MITRE ATT&CK T1110.001 – Brute Force: Password Guessing",
                "MITRE ATT&CK T1110.003 – Brute Force: Password Spraying",
                "OWASP A07:2021 – Identification and Authentication Failures",
                "NIST SP 800-63B §5.1.1 – Memorized Secret Authenticators",
                "CIS Control 5.2 – Use Unique Passwords",
            ],
            location=(
                f"{_ADMIN_SETTINGS_NAV}\n"
                "→ Scroll to 'Password complexity' → enable and configure minimum requirements → Apply"
            ),
        ))

    # ── Notification email ────────────────────────────────────────────────────
    notify = _val(admin, "NotificationEmail", "AdminEmail", "AlertEmail")
    if not notify:
        findings.append(Finding(
            severity=Severity.LOW,
            category="Administration",
            title="No admin notification email configured",
            detail="Without a notification email, critical alerts and security events may go unnoticed.",
            recommendation=(
                "Configure an admin notification email for system alerts and security events. "
                "Absence of alerting enables MITRE ATT&CK T1562 (Impair Defenses) — "
                "attackers rely on defenders not being notified of suspicious activity. "
                "Aligns with OWASP A09:2021 – Security Logging and Monitoring Failures."
            ),
            references=[
                "MITRE ATT&CK T1562 – Impair Defenses",
                "OWASP A09:2021 – Security Logging and Monitoring Failures",
                "CIS Control 8.11 – Conduct Audit Log Reviews",
            ],
            location=(
                "Administration → Notification settings\n"
                "→ Enter email address under 'Administrator email' → Apply"
            ),
        ))

    # ── Device access (zone-level admin access) ───────────────────────────────
    for da in cfg.device_access:
        zone = _val(da, "Zone", "Name")
        http = _val(da, "HTTP", "WebAdmin")
        ssh  = _val(da, "SSH")

        if zone.lower() in ("wan", "untrust", "internet", "external") or "wan" in zone.lower():
            if http.lower() not in ("disable", "disabled", "0", "false", "off", ""):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    category="Administration",
                    title=f"Web admin accessible from WAN zone ({zone})",
                    detail=(
                        f"Device access policy for zone '{zone}' permits HTTP/HTTPS "
                        "management access. Exposing the admin UI to the internet is extremely risky."
                    ),
                    recommendation=(
                        "Disable web admin access from WAN zones. Restrict management "
                        "to a dedicated out-of-band management network or VPN only. "
                        "Internet-exposed management enables MITRE ATT&CK T1190 (Exploit Public-Facing Application), "
                        "T1133 (External Remote Services), and T1110 (Brute Force). "
                        "Aligns with OWASP A01:2021 – Broken Access Control and "
                        "A05:2021 – Security Misconfiguration."
                    ),
                    references=[
                        "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                        "MITRE ATT&CK T1133 – External Remote Services",
                        "MITRE ATT&CK T1110 – Brute Force",
                        "OWASP A01:2021 – Broken Access Control",
                        "OWASP A05:2021 – Security Misconfiguration",
                        "CIS Control 12.3 – Securely Manage Network Infrastructure",
                        "CIS Sophos Benchmark §1.2",
                    ],
                    location=(
                        f"{_ADMIN_NAV}\n"
                        f"→ Find the '{zone}' zone row → uncheck 'HTTPS' and 'HTTP' "
                        "under the Admin column → Apply"
                    ),
                ))

            if ssh.lower() not in ("disable", "disabled", "0", "false", "off", ""):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category="Administration",
                    title=f"SSH access permitted from WAN zone ({zone})",
                    detail=(
                        f"SSH management is enabled for zone '{zone}'. "
                        "SSH brute-force and exploitation are common attack vectors against internet-exposed devices."
                    ),
                    recommendation=(
                        "Disable SSH from WAN. If required, restrict to a specific management IP "
                        "and use certificate-based authentication, never password-only. "
                        "Internet-exposed SSH enables MITRE ATT&CK T1133 (External Remote Services) "
                        "and T1110.001 (Password Guessing). "
                        "Aligns with OWASP A05:2021 – Security Misconfiguration."
                    ),
                    references=[
                        "MITRE ATT&CK T1133 – External Remote Services",
                        "MITRE ATT&CK T1110.001 – Brute Force: Password Guessing",
                        "MITRE ATT&CK T1021.004 – Remote Services: SSH",
                        "OWASP A05:2021 – Security Misconfiguration",
                        "CIS Control 4.6 – Securely Manage Enterprise Assets Remotely",
                    ],
                    location=(
                        f"{_ADMIN_NAV}\n"
                        f"→ Find the '{zone}' zone row → uncheck 'SSH' under the Admin column → Apply"
                    ),
                ))

    if not cfg.admin_settings and not cfg.device_access:
        findings.append(Finding(
            severity=Severity.INFO,
            category="Administration",
            title="Administration settings not found in config",
            detail="No AdministrationSettings or DeviceAccess elements were detected.",
            recommendation="Verify the backup is a full configuration export.",
        ))

    return findings

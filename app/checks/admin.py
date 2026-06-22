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
            exploitability="Medium", impact_scope="Host", exposure="Adjacent",
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
                exploitability="Medium", impact_scope="Host", exposure="Internal",
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
                exploitability="Low", impact_scope="Host", exposure="Internal",
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
            exploitability="Medium", impact_scope="Host", exposure="Internal",
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
            exploitability="Low", impact_scope="Local", exposure="Internal",
        ))

    # ── Device access (zone-level admin access) ───────────────────────────────
    _ssh_on_zones:   list[str] = []
    _ssh_dmz_zones:  list[str] = []
    _ssh_disabled_all = True  # assume disabled until we see it enabled anywhere

    for da in cfg.device_access:
        zone = _val(da, "Zone", "Name")
        http = _val(da, "HTTP", "WebAdmin")
        ssh  = _val(da, "SSH")
        is_wan = zone.lower() in ("wan", "untrust", "internet", "external") or "wan" in zone.lower()
        is_dmz = "dmz" in zone.lower() or "demil" in zone.lower()
        ssh_on = ssh.lower() not in ("disable", "disabled", "0", "false", "off", "")

        if ssh_on:
            _ssh_disabled_all = False
            _ssh_on_zones.append(zone)
            if is_dmz:
                _ssh_dmz_zones.append(zone)

        if is_wan:
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
                    exploitability="High", impact_scope="Host", exposure="External",
                ))

            if ssh_on:
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
                    exploitability="High", impact_scope="Host", exposure="External",
                ))

    # ── SSH visibility summary (all enabled zones) ────────────────────────────
    if not cfg.device_access:
        findings.append(Finding(
            severity=Severity.INFO,
            category="Administration",
            title="SSH access status could not be determined",
            detail=(
                "No DeviceAccess zone configuration was found in the backup. "
                "SSH management access status is unknown — verify manually."
            ),
            recommendation=(
                "In the Sophos admin console, navigate to Administration → Device access "
                "and confirm SSH is disabled on all zones unless explicitly required. "
                "If SSH is needed, restrict it to the LAN or management VLAN only."
            ),
            references=[
                "MITRE ATT&CK T1021.004 – Remote Services: SSH",
                "CIS Control 4.6 – Securely Manage Enterprise Assets Remotely",
            ],
            location=f"{_ADMIN_NAV}\n→ Review SSH column for each zone",
            exploitability="Low", impact_scope="Host", exposure="Internal",
        ))
    elif _ssh_disabled_all:
        findings.append(Finding(
            severity=Severity.INFO,
            category="Administration",
            title="SSH management access is disabled on all zones",
            detail="SSH is disabled across all device access zones. This is the recommended posture.",
            recommendation=(
                "No action required. Continue to verify this setting after firmware upgrades "
                "as updates can sometimes re-enable default services."
            ),
            references=[
                "CIS Control 4.6 – Securely Manage Enterprise Assets Remotely",
            ],
            location=f"{_ADMIN_NAV}\n→ SSH column — all zones show Disabled",
            exploitability="Low", impact_scope="Local", exposure="Internal",
        ))
    else:
        findings.append(Finding(
            severity=Severity.LOW,
            category="Administration",
            title=f"SSH management access is enabled on {len(_ssh_on_zones)} zone(s)",
            detail=(
                f"SSH is enabled on: {', '.join(_ssh_on_zones)}. "
                "SSH provides command-line access to the firewall. "
                "Even on internal zones it increases attack surface if an internal host is compromised."
            ),
            recommendation=(
                "Disable SSH on all zones where it is not actively required. "
                "If SSH is needed for maintenance, enable it only temporarily and restrict access "
                "to a dedicated management VLAN or host IP. "
                "Enabled SSH on internal zones enables MITRE ATT&CK T1021.004 (Remote Services: SSH) "
                "lateral movement from a compromised internal host. "
                "Aligns with CIS Control 4.6 – Securely Manage Enterprise Assets Remotely."
            ),
            references=[
                "MITRE ATT&CK T1021.004 – Remote Services: SSH",
                "MITRE ATT&CK T1133 – External Remote Services",
                "OWASP A05:2021 – Security Misconfiguration",
                "CIS Control 4.6 – Securely Manage Enterprise Assets Remotely",
            ],
            location=(
                f"{_ADMIN_NAV}\n"
                "→ For each zone where SSH is not required → uncheck SSH under Admin column → Apply"
            ),
            affected=_ssh_on_zones,
            exploitability="Low", impact_scope="Host", exposure="Internal",
        ))

    # SSH on DMZ — elevated risk even if not WAN
    if _ssh_dmz_zones:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="Administration",
            title=f"SSH enabled on DMZ zone(s) ({', '.join(_ssh_dmz_zones)})",
            detail=(
                "SSH is enabled on a DMZ zone. DMZ hosts are typically externally reachable "
                "and a compromised DMZ server can pivot to the firewall management interface via SSH."
            ),
            recommendation=(
                "Disable SSH on all DMZ zones. DMZ-to-firewall SSH enables MITRE ATT&CK "
                "T1021.004 (Remote Services: SSH) as a pivot from a compromised DMZ server "
                "directly to firewall management. "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            references=[
                "MITRE ATT&CK T1021.004 – Remote Services: SSH",
                "MITRE ATT&CK TA0008 – Lateral Movement",
                "OWASP A05:2021 – Security Misconfiguration",
                "CIS Control 12.2 – Establish and Maintain a Secure Network Architecture",
            ],
            location=(
                f"{_ADMIN_NAV}\n"
                "→ Find the DMZ zone row → uncheck SSH under Admin column → Apply"
            ),
            affected=_ssh_dmz_zones,
            exploitability="Medium", impact_scope="Host", exposure="Adjacent",
        ))

    # ── CIS 1.1.2 – Login disclaimer ─────────────────────────────────────────
    disclaimer = _val(admin, "LoginDisclaimer", "BannerMessage", "LoginBanner", "Disclaimer")
    if _off(disclaimer) or not disclaimer:
        findings.append(Finding(
            severity=Severity.LOW,
            category="Administration",
            title="CIS 1.1.2 – Login disclaimer / banner not configured",
            detail=(
                "No login banner or disclaimer is configured. A legal login banner notifies "
                "users that the system is monitored, provides legal notice for acceptable use, "
                "and is required by many compliance frameworks."
            ),
            recommendation=(
                "Enable a login disclaimer under System → Administration → Device Access → "
                "Login disclaimer. Include: 'Authorised users only. This system is monitored.' "
                "Aligns with CIS Sophos Benchmark §1.1.2."
            ),
            references=[
                "CIS Sophos Benchmark §1.1.2",
                "NIST SP 800-53 Rev 5 AC-8 – System Use Notification",
            ],
            location=(
                "Administration → Device access\n"
                "→ Login disclaimer → Enable → Enter disclaimer text → Apply"
            ),
            exploitability="Low", impact_scope="Local", exposure="Internal",
        ))

    # ── CIS 1.1.7 – Valid certificate for webadmin interface ─────────────────
    web_cert = _val(admin, "WebAdminCertificate", "AdminCertificate", "Certificate",
                    "HTTPSCertificate", "WebServerCertificate")
    if not web_cert or web_cert.lower() in ("default", "self-signed", "selfsigned", "factory"):
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="Administration",
            title="CIS 1.1.7 – Default/self-signed certificate used for webadmin interface",
            detail=(
                "The web admin interface is using a default or self-signed certificate. "
                "Browsers cannot verify the identity of the management console, opening the "
                "door to man-in-the-middle attacks against administrator sessions."
            ),
            recommendation=(
                "Replace the default certificate with one issued by a trusted internal CA or "
                "public CA. Navigate to Administration → Admin and user settings → "
                "select a valid certificate for the HTTPS admin interface. "
                "Aligns with CIS Sophos Benchmark §1.1.7."
            ),
            references=[
                "CIS Sophos Benchmark §1.1.7",
                "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                "OWASP A02:2021 – Cryptographic Failures",
            ],
            location=(
                "Administration → Admin and user settings\n"
                "→ Certificate for HTTPS → select a CA-signed certificate → Apply"
            ),
            exploitability="Medium", impact_scope="Host", exposure="Adjacent",
        ))

    # ── CIS 1.1.8/1.1.9 – MFA for web console, VPN, and default admin ────────
    mfa = cfg.mfa_settings
    mfa_webconsole = _val(mfa, "WebAdminMFA", "WebConsoleMFA", "RequireMFAWebAdmin",
                          "MFAWebAdmin", "WebAdmin") if mfa else ""
    mfa_vpn = _val(mfa, "SSLVPNMFA", "VPNMFARequired", "RequireMFAVPN",
                   "MFARemoteAccess", "SSLVPN") if mfa else ""
    mfa_default_admin = _val(mfa, "DefaultAdminMFA", "AdminMFA", "MFADefaultAdmin",
                              "DefaultAdmin") if mfa else ""

    if mfa and _off(mfa_webconsole):
        findings.append(Finding(
            severity=Severity.HIGH,
            category="Administration",
            title="CIS 1.1.8 – MFA not required for web admin console access",
            detail=(
                "Multi-factor authentication is not enforced for web admin console access. "
                "A stolen admin password gives full firewall control without any second factor."
            ),
            recommendation=(
                "Navigate to Authentication → Multi-factor authentication → MFA Settings → "
                "enable 'Require MFA for Web admin console'. "
                "Aligns with CIS Sophos Benchmark §1.1.8 and CIS Control 6.5."
            ),
            references=[
                "CIS Sophos Benchmark §1.1.8",
                "CIS Control 6.5 – Require MFA for Administrative Access",
                "MITRE ATT&CK T1078 – Valid Accounts",
            ],
            location=(
                "Authentication → Multi-factor authentication → MFA Settings\n"
                "→ Require MFA for 'Web admin console' → Enable → Apply"
            ),
            exploitability="High", impact_scope="Host", exposure="External",
        ))

    if mfa and _off(mfa_vpn):
        findings.append(Finding(
            severity=Severity.HIGH,
            category="Administration",
            title="CIS 1.1.8 – MFA not required for remote access VPN",
            detail=(
                "MFA is not enforced for SSL VPN or IPSec remote access. "
                "A compromised VPN credential provides direct network access without a second factor."
            ),
            recommendation=(
                "Enable MFA for SSL VPN and IPSec remote access under "
                "Authentication → Multi-factor authentication → MFA Settings. "
                "Aligns with CIS Sophos Benchmark §1.1.8 and CIS Control 6.4."
            ),
            references=[
                "CIS Sophos Benchmark §1.1.8",
                "CIS Control 6.4 – Require MFA for Remote Network Access",
                "MITRE ATT&CK T1133 – External Remote Services",
            ],
            location=(
                "Authentication → Multi-factor authentication → MFA Settings\n"
                "→ Require MFA for 'SSL VPN remote access' and 'IPSec remote access' → Apply"
            ),
            exploitability="High", impact_scope="Network", exposure="External",
        ))

    if mfa and _off(mfa_default_admin):
        findings.append(Finding(
            severity=Severity.HIGH,
            category="Administration",
            title="CIS 1.1.9 – MFA not enabled for default admin account",
            detail=(
                "MFA is not enabled for the default administrator account specifically. "
                "The benchmark requires explicit MFA for the built-in admin account under "
                "System → Administration → Device Access."
            ),
            recommendation=(
                "Navigate to System → Administration → Device Access → "
                "Multi-factor Authentication for default admin → Turn ON. "
                "Aligns with CIS Sophos Benchmark §1.1.9."
            ),
            references=[
                "CIS Sophos Benchmark §1.1.9",
                "CIS Control 6.5 – Require MFA for Administrative Access",
                "MITRE ATT&CK T1078.001 – Default Accounts",
            ],
            location=(
                "System → Administration → Device Access\n"
                "→ Multi-factor Authentication for default admin → Turn ON"
            ),
            exploitability="High", impact_scope="Host", exposure="External",
        ))

    # ── CIS 1.1.10 – Hostname must be set ────────────────────────────────────
    hostname = _val(admin, "Hostname", "DeviceName", "SystemName", "HostName")
    if not hostname:
        # Also check system_settings
        hostname = _val(cfg.system_settings, "Hostname", "DeviceName", "SystemName", "HostName")
    if not hostname or hostname.lower() in ("sophos", "sfos", "xg", "firewall", "default", ""):
        findings.append(Finding(
            severity=Severity.LOW,
            category="Administration",
            title="CIS 1.1.10 – Hostname not configured or set to default",
            detail=(
                "The device hostname is not set or uses a generic default. "
                "A meaningful hostname ensures logs, SNMP traps, and Sophos Central events "
                "can be attributed to the correct device — critical in multi-firewall environments."
            ),
            recommendation=(
                "Set a descriptive hostname (e.g. FW-HQ-EDGE01) under "
                "Administration → Device Access → Hostname. "
                "Aligns with CIS Sophos Benchmark §1.1.10."
            ),
            references=[
                "CIS Sophos Benchmark §1.1.10",
                "NIST SP 800-92 – Guide to Computer Security Log Management",
            ],
            location=(
                "Administration → Device Access → Hostname\n"
                "→ Set a descriptive hostname → Apply"
            ),
            exploitability="Low", impact_scope="Local", exposure="Internal",
        ))

    if not cfg.admin_settings and not cfg.device_access:
        findings.append(Finding(
            severity=Severity.INFO,
            category="Administration",
            title="Administration settings not found in config",
            detail="No AdministrationSettings or DeviceAccess elements were detected.",
            recommendation="Verify the backup is a full configuration export.",
            exploitability="Low", impact_scope="Local", exposure="Internal",
        ))

    return findings

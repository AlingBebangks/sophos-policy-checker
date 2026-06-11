"""Administration and device access checks."""
from .models import Finding, Severity


def _val(d: dict, *keys: str) -> str:
    for k in keys:
        v = d.get(k, "")
        if v:
            return str(v).strip()
    return ""


def run(cfg) -> list[Finding]:
    findings: list[Finding] = []
    admin = cfg.admin_settings

    # ── HTTP management ───────────────────────────────────────────────────────
    http_enabled = _val(admin, "HTTPSPort", "HTTPPort", "WebAdminHTTP")
    admin_port = _val(admin, "HTTPSPort", "AdminPort")
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
                "Disable HTTP management access. Enforce HTTPS-only with a valid "
                "certificate. Redirect HTTP to HTTPS if needed."
            ),
            references=["CIS Sophos Benchmark §1.1"],
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
                recommendation="Set the admin session timeout to 15 minutes or less.",
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
                recommendation="Reduce admin session timeout to 15 minutes or less.",
            ))
    except (ValueError, TypeError):
        pass

    # ── Password complexity ───────────────────────────────────────────────────
    complexity = _val(admin, "PasswordComplexity", "AdminPasswordComplexity")
    if complexity.lower() in ("disable", "disabled", "0", "false", "off", ""):
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="Administration",
            title="Admin password complexity enforcement not detected",
            detail=(
                "Password complexity enforcement was not found or is disabled. "
                "Weak admin passwords are a leading cause of firewall compromise."
            ),
            recommendation=(
                "Enable password complexity requirements: minimum 12 characters, "
                "upper/lowercase, numbers, and special characters."
            ),
        ))

    # ── Notification email ────────────────────────────────────────────────────
    notify = _val(admin, "NotificationEmail", "AdminEmail", "AlertEmail")
    if not notify:
        findings.append(Finding(
            severity=Severity.LOW,
            category="Administration",
            title="No admin notification email configured",
            detail="Without a notification email, critical alerts may go unnoticed.",
            recommendation="Configure an admin notification email for system alerts and security events.",
        ))

    # ── Device access (zone-level admin access) ───────────────────────────────
    for da in cfg.device_access:
        zone = _val(da, "Zone", "Name")
        http = _val(da, "HTTP", "WebAdmin")
        ping = _val(da, "Ping", "ICMP")
        ssh = _val(da, "SSH")

        if zone.lower() in ("wan", "untrust", "internet", "external") or "wan" in zone.lower():
            if http.lower() not in ("disable", "disabled", "0", "false", "off", ""):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    category="Administration",
                    title=f"Web admin accessible from WAN zone ({zone})",
                    detail=(
                        f"Device access policy for zone '{zone}' permits HTTP/HTTPS "
                        "management access. Exposing admin UI to the internet is extremely risky."
                    ),
                    recommendation=(
                        "Disable web admin access from WAN zones. Restrict management "
                        "to a dedicated out-of-band management network or VPN only."
                    ),
                    references=["CIS Sophos Benchmark §1.2"],
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
                        "and use certificate-based authentication."
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

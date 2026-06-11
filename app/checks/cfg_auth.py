"""Config checks — Authentication, users, MFA, password policy."""
from .models import Finding, Severity

_S = "Config — Authentication"


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

    # ── MFA ───────────────────────────────────────────────────────────────────
    mfa = cfg.mfa_settings
    if not mfa:
        findings.append(Finding(
            severity=Severity.HIGH,
            category=_S,
            title="Multi-factor authentication settings not found",
            detail=(
                "MFA configuration was not detected. If MFA is not enforced for admin access, "
                "a compromised password gives an attacker full control of the firewall."
            ),
            recommendation="Enable MFA (TOTP or hardware token) for all administrator accounts.",
            location="Authentication → Multi-factor authentication\n→ Enable MFA → assign to admin profiles → Apply",
        ))
    else:
        status = _v(mfa, "Status", "Enable", "Enabled", "State")
        if _off(status):
            findings.append(Finding(
                severity=Severity.HIGH,
                category=_S,
                title="Multi-factor authentication is disabled",
                detail="Disabling MFA means admin access relies on password alone — a single credential leak is sufficient for full compromise.",
                recommendation="Enable MFA for all administrator accounts immediately.",
                location="Authentication → Multi-factor authentication → Enable → Apply",
                references=["NIST SP 800-63B §5.1", "CIS Control 6.5"],
            ))

    # ── Password Policy ───────────────────────────────────────────────────────
    pp = cfg.password_policy
    if not pp:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="Password policy not found",
            detail="No password policy configuration was detected. Weak passwords may be in use.",
            recommendation="Configure and enforce a strong password policy for all accounts.",
            location="Authentication → Password policy → Configure complexity and minimum length → Apply",
        ))
    else:
        min_len = _v(pp, "MinimumLength", "MinLength", "PasswordMinLength")
        try:
            if int(min_len) < 12:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=_S,
                    title=f"Minimum password length too short ({min_len} characters)",
                    detail=f"A minimum of {min_len} characters does not meet modern standards. Short passwords are vulnerable to brute force.",
                    recommendation="Set minimum password length to 14 or more characters.",
                    location="Authentication → Password policy → Minimum length → set to 14+ → Apply",
                    references=["NIST SP 800-63B"],
                ))
        except (ValueError, TypeError):
            pass

        complexity = _v(pp, "Complexity", "PasswordComplexity", "ComplexityEnable")
        if _off(complexity):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=_S,
                title="Password complexity not enforced",
                detail="Without complexity rules, users can set trivial passwords (e.g. 'password123').",
                recommendation="Require uppercase, lowercase, numbers, and special characters.",
                location="Authentication → Password policy → Enable complexity rules → Apply",
            ))

        lockout = _v(pp, "AccountLockout", "LockoutThreshold", "MaxAttempts", "FailedAttempts")
        if _off(lockout) or lockout == "0":
            findings.append(Finding(
                severity=Severity.HIGH,
                category=_S,
                title="Account lockout policy not configured",
                detail="Without lockout, brute-force and credential-stuffing attacks can attempt unlimited password guesses.",
                recommendation="Set account lockout after 5 failed attempts with a 15-minute lockout duration.",
                location="Authentication → Password policy → Account lockout → Enable → set threshold to 5 → Apply",
                references=["CIS Control 5.2"],
            ))
        else:
            try:
                if int(lockout) > 10:
                    findings.append(Finding(
                        severity=Severity.LOW,
                        category=_S,
                        title=f"Account lockout threshold is high ({lockout} attempts)",
                        detail=f"Allowing {lockout} failed attempts before lockout gives attackers significant brute-force headroom.",
                        recommendation="Reduce lockout threshold to 5 failed attempts.",
                        location="Authentication → Password policy → Account lockout threshold → reduce to 5 → Apply",
                    ))
            except (ValueError, TypeError):
                pass

        expiry = _v(pp, "PasswordExpiry", "MaxAge", "PasswordAge", "ExpiryDays")
        if _off(expiry) or expiry == "0":
            findings.append(Finding(
                severity=Severity.LOW,
                category=_S,
                title="Password expiry not enforced",
                detail="Passwords that never expire remain valid indefinitely if compromised.",
                recommendation="Set password expiry to 90 days for admin accounts.",
                location="Authentication → Password policy → Password expiry → set to 90 days → Apply",
            ))

        history = _v(pp, "PasswordHistory", "HistoryCount", "ReuseCount")
        try:
            if not history or int(history) < 5:
                findings.append(Finding(
                    severity=Severity.LOW,
                    category=_S,
                    title="Password history too short or not configured",
                    detail="Without password history enforcement, users can cycle back to the same password immediately.",
                    recommendation="Prevent reuse of the last 10 passwords.",
                    location="Authentication → Password policy → Password history → set to 10 → Apply",
                ))
        except (ValueError, TypeError):
            pass

    # ── External Auth (RADIUS/LDAP) ───────────────────────────────────────────
    if not cfg.auth_servers:
        findings.append(Finding(
            severity=Severity.INFO,
            category=_S,
            title="No external authentication server configured",
            detail=(
                "Only local authentication is in use. External auth (RADIUS, LDAP, AD) enables "
                "centralised credential management, audit logging, and immediate account revocation."
            ),
            recommendation="Integrate with RADIUS, LDAP, or Active Directory for centralised authentication.",
            location="Authentication → Servers → Add RADIUS/LDAP/AD server → Apply",
        ))
    else:
        for srv in cfg.auth_servers:
            name = _v(srv, "Name", "ServerName")
            stype = srv.get("_type", "")
            # Check RADIUS for unencrypted (port 1812 without TLS is expected but log it)
            if stype == "RADIUSServer":
                enc = _v(srv, "Encryption", "TLS", "SecureTransport")
                if _off(enc):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        category=_S,
                        title=f"RADIUS server '{name}' not using encrypted transport",
                        detail="Standard RADIUS transmits authentication data with weak MD5-based protection. Use RADSEC (RADIUS over TLS) where possible.",
                        recommendation="Upgrade to RADSEC (port 2083 over TLS) or ensure RADIUS traffic is confined to a secure management VLAN.",
                        location=f"Authentication → Servers → Edit '{name}' → enable TLS → Apply",
                    ))
            if stype == "LDAPServer":
                port = _v(srv, "Port", "ServerPort")
                if port == "389":
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=_S,
                        title=f"LDAP server '{name}' using cleartext port 389",
                        detail="LDAP on port 389 transmits credentials in cleartext. An attacker on the management network can capture AD credentials.",
                        recommendation="Switch to LDAPS (port 636) or LDAP with STARTTLS.",
                        location=f"Authentication → Servers → Edit '{name}' → change port to 636 / enable SSL → Apply",
                    ))

    # ── Local Admin Accounts ──────────────────────────────────────────────────
    admin_users = [u for u in cfg.local_users if "admin" in u.get("role", "").lower()]
    default_admin = [u for u in cfg.local_users if u.get("name", "").lower() == "admin"]

    if default_admin:
        findings.append(Finding(
            severity=Severity.HIGH,
            category=_S,
            title="Default 'admin' account still active",
            detail="The default administrator account name is well-known and is a common target for credential attacks.",
            recommendation="Create a named administrator account and disable or rename the default 'admin' account.",
            location="System → Administration → Admin and user settings → Administrators\n→ Create new admin → disable default 'admin' account",
        ))

    if len(admin_users) > 3:
        findings.append(Finding(
            severity=Severity.LOW,
            category=_S,
            title=f"Large number of administrator accounts ({len(admin_users)})",
            detail="Excessive admin accounts increase the attack surface and make access reviews harder.",
            recommendation="Review all admin accounts. Remove or demote accounts that are no longer needed.",
            location="System → Administration → Admin and user settings → Administrators → review and remove unused accounts",
            affected=[u.get("name", "(unnamed)") for u in admin_users],
        ))

    return findings

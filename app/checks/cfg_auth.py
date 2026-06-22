"""Config checks — Authentication, users, MFA, password policy."""
from .models import Finding, Severity
from .utils import v as _v, off as _off

_S = "Config — Authentication"


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
            recommendation=(
                "Enable MFA (TOTP or hardware token) for all administrator accounts. "
                "Without MFA, MITRE ATT&CK T1078 (Valid Accounts) and T1110 (Brute Force) "
                "give an attacker full firewall control with only a password. "
                "MFA mitigates over 99% of account-takeover attacks (Microsoft threat research). "
                "Aligns with OWASP A07:2021 – Identification and Authentication Failures."
            ),
            references=[
                "MITRE ATT&CK T1078 – Valid Accounts",
                "MITRE ATT&CK T1110 – Brute Force",
                "MITRE ATT&CK Mitigation M1032 – Multi-factor Authentication",
                "OWASP A07:2021 – Identification and Authentication Failures",
                "NIST SP 800-63B §5.1 – Authenticator Requirements",
                "CIS Control 6.5 – Require MFA for Administrative Access",
            ],
            location="Authentication → Multi-factor authentication\n→ Enable MFA → assign to admin profiles → Apply",
            exploitability="High", impact_scope="Host", exposure="External",
        ))
    else:
        status = _v(mfa, "Status", "Enable", "Enabled", "State")
        if _off(status):
            findings.append(Finding(
                severity=Severity.HIGH,
                category=_S,
                title="Multi-factor authentication is disabled",
                detail="Disabling MFA means admin access relies on password alone — a single credential leak is sufficient for full compromise.",
                recommendation=(
                    "Enable MFA for all administrator accounts immediately. "
                    "Disabled MFA enables MITRE ATT&CK T1078 (Valid Accounts) and T1110 (Brute Force) — "
                    "password-only admin access is the #1 cause of firewall compromise in incident response. "
                    "Aligns with OWASP A07:2021 – Identification and Authentication Failures."
                ),
                references=[
                    "MITRE ATT&CK T1078 – Valid Accounts",
                    "MITRE ATT&CK T1110 – Brute Force",
                    "MITRE ATT&CK Mitigation M1032 – Multi-factor Authentication",
                    "OWASP A07:2021 – Identification and Authentication Failures",
                    "NIST SP 800-63B §5.1",
                    "CIS Control 6.5 – Require MFA for Administrative Access",
                ],
                location="Authentication → Multi-factor authentication → Enable → Apply",
                exploitability="High", impact_scope="Host", exposure="External",
            ))

    # ── Password Policy ───────────────────────────────────────────────────────
    pp = cfg.password_policy
    if not pp:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="Password policy not found",
            detail="No password policy configuration was detected. Weak passwords may be in use.",
            recommendation=(
                "Configure and enforce a strong password policy for all accounts. "
                "Aligns with OWASP A07:2021 – Identification and Authentication Failures."
            ),
            references=[
                "MITRE ATT&CK T1110 – Brute Force",
                "OWASP A07:2021 – Identification and Authentication Failures",
            ],
            location="Authentication → Password policy → Configure complexity and minimum length → Apply",
            exploitability="Medium", impact_scope="Host", exposure="Internal",
        ))
    else:
        min_len = _v(pp, "MinimumLength", "MinLength", "PasswordMinLength")
        try:
            if int(min_len) < 12:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=_S,
                    title=f"Minimum password length too short ({min_len} characters)",
                    detail=f"A minimum of {min_len} characters does not meet modern standards. Short passwords are vulnerable to brute force and dictionary attacks.",
                    recommendation=(
                        "Set minimum password length to 14 or more characters. "
                        "Short passwords enable MITRE ATT&CK T1110.001 (Password Guessing) and "
                        "T1110.002 (Password Cracking) — 8-character passwords are cracked in minutes with GPUs. "
                        "Aligns with OWASP A07:2021 – Identification and Authentication Failures and "
                        "NIST SP 800-63B (recommends length over complexity)."
                    ),
                    references=[
                        "MITRE ATT&CK T1110.001 – Brute Force: Password Guessing",
                        "MITRE ATT&CK T1110.002 – Brute Force: Password Cracking",
                        "OWASP A07:2021 – Identification and Authentication Failures",
                        "NIST SP 800-63B §5.1.1 – Memorized Secret Authenticators",
                    ],
                    location="Authentication → Password policy → Minimum length → set to 14+ → Apply",
                    exploitability="Medium", impact_scope="Host", exposure="External",
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
                recommendation=(
                    "Require uppercase, lowercase, numbers, and special characters. "
                    "Simple passwords enable MITRE ATT&CK T1110.001 (Password Guessing). "
                    "Aligns with OWASP A07:2021 – Identification and Authentication Failures."
                ),
                references=[
                    "MITRE ATT&CK T1110.001 – Brute Force: Password Guessing",
                    "OWASP A07:2021 – Identification and Authentication Failures",
                    "CIS Control 5.2 – Use Unique Passwords",
                ],
                location="Authentication → Password policy → Enable complexity rules → Apply",
                exploitability="Medium", impact_scope="Host", exposure="Internal",
            ))

        lockout = _v(pp, "AccountLockout", "LockoutThreshold", "MaxAttempts", "FailedAttempts")
        if _off(lockout) or lockout == "0":
            findings.append(Finding(
                severity=Severity.HIGH,
                category=_S,
                title="Account lockout policy not configured",
                detail="Without lockout, brute-force and credential-stuffing attacks can attempt unlimited password guesses.",
                recommendation=(
                    "Set account lockout after 5 failed attempts with a 15-minute lockout duration. "
                    "Missing lockout enables MITRE ATT&CK T1110.003 (Password Spraying) — "
                    "attackers automate thousands of guesses without triggering any defence. "
                    "Aligns with OWASP A07:2021 – Identification and Authentication Failures."
                ),
                references=[
                    "MITRE ATT&CK T1110.003 – Brute Force: Password Spraying",
                    "MITRE ATT&CK T1110.001 – Brute Force: Password Guessing",
                    "MITRE ATT&CK Mitigation M1036 – Account Use Policies",
                    "OWASP A07:2021 – Identification and Authentication Failures",
                    "CIS Control 5.2 – Use Unique Passwords",
                ],
                location="Authentication → Password policy → Account lockout → Enable → set threshold to 5 → Apply",
                exploitability="High", impact_scope="Host", exposure="External",
            ))
        else:
            try:
                if int(lockout) > 10:
                    findings.append(Finding(
                        severity=Severity.LOW,
                        category=_S,
                        title=f"Account lockout threshold is high ({lockout} attempts)",
                        detail=f"Allowing {lockout} failed attempts before lockout gives attackers significant brute-force headroom.",
                        recommendation=(
                            "Reduce lockout threshold to 5 failed attempts. "
                            "Aligns with MITRE ATT&CK Mitigation M1036 (Account Use Policies)."
                        ),
                        references=[
                            "MITRE ATT&CK Mitigation M1036 – Account Use Policies",
                            "OWASP A07:2021 – Identification and Authentication Failures",
                        ],
                        location="Authentication → Password policy → Account lockout threshold → reduce to 5 → Apply",
                        exploitability="Medium", impact_scope="Host", exposure="External",
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
                recommendation=(
                    "Set password expiry to 90 days for admin accounts. "
                    "Perpetual credentials extend the damage window of "
                    "MITRE ATT&CK T1078 (Valid Accounts) — a stolen password stays valid forever. "
                    "Aligns with OWASP A07:2021 – Identification and Authentication Failures."
                ),
                references=[
                    "MITRE ATT&CK T1078 – Valid Accounts",
                    "OWASP A07:2021 – Identification and Authentication Failures",
                    "NIST SP 800-63B §5.1.1",
                ],
                location="Authentication → Password policy → Password expiry → set to 90 days → Apply",
                exploitability="Low", impact_scope="Host", exposure="Internal",
            ))

        history = _v(pp, "PasswordHistory", "HistoryCount", "ReuseCount")
        try:
            if not history or int(history) < 5:
                findings.append(Finding(
                    severity=Severity.LOW,
                    category=_S,
                    title="Password history too short or not configured",
                    detail="Without password history enforcement, users can cycle back to the same password immediately.",
                    recommendation=(
                        "Prevent reuse of the last 10 passwords. "
                        "Aligns with OWASP A07:2021 – Identification and Authentication Failures."
                    ),
                    references=[
                        "OWASP A07:2021 – Identification and Authentication Failures",
                        "NIST SP 800-63B §5.1.1",
                    ],
                    location="Authentication → Password policy → Password history → set to 10 → Apply",
                    exploitability="Low", impact_scope="Host", exposure="Internal",
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
            recommendation=(
                "Integrate with RADIUS, LDAP, or Active Directory for centralised authentication. "
                "Centralised auth enables rapid revocation, reducing the dwell time of "
                "MITRE ATT&CK T1078 (Valid Accounts) after a compromise. "
                "Aligns with OWASP A07:2021 – Identification and Authentication Failures."
            ),
            references=[
                "MITRE ATT&CK T1078 – Valid Accounts",
                "OWASP A07:2021 – Identification and Authentication Failures",
            ],
            location="Authentication → Servers → Add RADIUS/LDAP/AD server → Apply",
            exploitability="Low", impact_scope="Local", exposure="Internal",
        ))
    else:
        for srv in cfg.auth_servers:
            name  = _v(srv, "Name", "ServerName")
            stype = srv.get("_type", "")
            if stype == "RADIUSServer":
                enc = _v(srv, "Encryption", "TLS", "SecureTransport")
                if _off(enc):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        category=_S,
                        title=f"RADIUS server '{name}' not using encrypted transport",
                        detail="Standard RADIUS transmits authentication data with weak MD5-based protection. Use RADSEC (RADIUS over TLS) where possible.",
                        recommendation=(
                            "Upgrade to RADSEC (port 2083 over TLS) or ensure RADIUS traffic is confined to a secure management VLAN. "
                            "Unencrypted RADIUS enables MITRE ATT&CK T1040 (Network Sniffing) — "
                            "an attacker capturing RADIUS packets can crack the MD5-protected password offline. "
                            "Aligns with OWASP A02:2021 – Cryptographic Failures."
                        ),
                        references=[
                            "MITRE ATT&CK T1040 – Network Sniffing",
                            "OWASP A02:2021 – Cryptographic Failures",
                            "RFC 6614 – Transport Layer Security (TLS) Encryption for RADIUS (RADSEC)",
                        ],
                        location=f"Authentication → Servers → Edit '{name}' → enable TLS → Apply",
                        exploitability="Medium", impact_scope="Network", exposure="Adjacent",
                    ))
            if stype == "LDAPServer":
                port = _v(srv, "Port", "ServerPort")
                if port == "389":
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=_S,
                        title=f"LDAP server '{name}' using cleartext port 389",
                        detail="LDAP on port 389 transmits credentials in cleartext. An attacker on the management network can capture Active Directory credentials.",
                        recommendation=(
                            "Switch to LDAPS (port 636) or LDAP with STARTTLS. "
                            "Cleartext LDAP enables MITRE ATT&CK T1040 (Network Sniffing) and "
                            "T1557 (Adversary-in-the-Middle) — AD service account credentials travel in the clear. "
                            "Aligns with OWASP A02:2021 – Cryptographic Failures."
                        ),
                        references=[
                            "MITRE ATT&CK T1040 – Network Sniffing",
                            "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                            "OWASP A02:2021 – Cryptographic Failures",
                            "RFC 4513 – LDAP Authentication Methods and Security Mechanisms",
                        ],
                        location=f"Authentication → Servers → Edit '{name}' → change port to 636 / enable SSL → Apply",
                        exploitability="High", impact_scope="Network", exposure="Adjacent",
                    ))

    # ── CIS 2.1 – Firewall rules identify users before authorizing access ────
    # Identify LAN/DMZ-sourced accept rules missing user identity matching
    rules_no_user_id = [
        r.get("name", f"Rule #{r.get('policy_index','?')}")
        for r in cfg.firewall_rules
        if r.get("action", "").lower() in ("accept", "allow")
        and any(z.strip().lower() in ("lan", "internal", "dmz", "users", "corp", "office")
                or "lan" in z.lower() or "internal" in z.lower()
                for z in r.get("src_zones", []))
        and not r.get("user_identity", "").strip()
    ]
    if rules_no_user_id:
        findings.append(Finding(
            severity=Severity.LOW,
            category=_S,
            title="CIS 2.1 – Firewall rules missing user identity matching",
            detail=(
                "LAN/DMZ-sourced accept rules do not have 'Match known users' configured. "
                "The benchmark requires that users are identified and authenticated before "
                "network resources are authorised, enabling user-based logging and incident response."
            ),
            recommendation=(
                "Edit each affected rule → enable 'Match known users' and specify authorised "
                "user groups. Configure an authentication server under "
                "Configure → Authentication → Services. "
                "Aligns with CIS Sophos Benchmark §2.1."
            ),
            references=[
                "CIS Sophos Benchmark §2.1",
                "CIS Control 8.2 – Collect Audit Logs",
                "MITRE ATT&CK T1078 – Valid Accounts",
            ],
            location=(
                "Firewall → Rules and policies → Firewall rules\n"
                "→ Edit rule → Identity → enable 'Match known users' → assign user groups → Save"
            ),
            affected=rules_no_user_id[:20],
            exploitability="Low", impact_scope="Network", exposure="Internal",
        ))

    # ── CIS 2.2 – Encrypted LDAP/AD connection ───────────────────────────────
    # (already implemented above; also add validation for 'Validate server certificate')
    for srv in cfg.auth_servers:
        stype = srv.get("_type", "")
        name  = _v(srv, "Name", "ServerName")
        if stype in ("LDAPServer", "ActiveDirectory"):
            conn_sec = _v(srv, "ConnectionSecurity", "Encryption", "TLS", "SecureTransport",
                          "SSL", "LDAPS", "Protocol")
            validate_cert = _v(srv, "ValidateCertificate", "ValidateServerCert",
                                "CertificateValidation")
            if conn_sec.lower() in ("none", "plaintext", "unencrypted", ""):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=_S,
                    title=f"CIS 2.2 – LDAP/AD server '{name}' uses no connection security",
                    detail=(
                        f"LDAP/AD server '{name}' does not use SSL/TLS or STARTTLS. "
                        "Directory credentials and queries are transmitted in cleartext."
                    ),
                    recommendation=(
                        "Set connection security to SSL/TLS (LDAPS) or STARTTLS and "
                        "enable 'Validate server certificate'. "
                        "Aligns with CIS Sophos Benchmark §2.2."
                    ),
                    references=[
                        "CIS Sophos Benchmark §2.2",
                        "CIS Control 12.3 – Securely Manage Network Infrastructure",
                        "MITRE ATT&CK T1040 – Network Sniffing",
                    ],
                    location=f"Authentication → Servers → Edit '{name}' → SSL/TLS → Apply",
                    exploitability="High", impact_scope="Network", exposure="Adjacent",
                ))
            elif _off(validate_cert):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=_S,
                    title=f"CIS 2.2 – LDAP/AD server '{name}' does not validate server certificate",
                    detail=(
                        f"Encrypted LDAP is configured for '{name}' but certificate validation is off. "
                        "Without validation, the connection is vulnerable to MITM even with TLS."
                    ),
                    recommendation=(
                        "Enable 'Validate server certificate' for LDAP/AD connections. "
                        "Aligns with CIS Sophos Benchmark §2.2."
                    ),
                    references=[
                        "CIS Sophos Benchmark §2.2",
                        "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                    ],
                    location=f"Authentication → Servers → Edit '{name}' → Validate server certificate → Apply",
                    exploitability="Medium", impact_scope="Network", exposure="Adjacent",
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
            recommendation=(
                "Create a named administrator account and disable or rename the default 'admin' account. "
                "Default accounts enable MITRE ATT&CK T1078.001 (Default Accounts) — "
                "attackers try 'admin/admin' and 'admin/password' as first steps in every attack. "
                "Aligns with OWASP A07:2021 – Identification and Authentication Failures."
            ),
            references=[
                "MITRE ATT&CK T1078.001 – Valid Accounts: Default Accounts",
                "OWASP A07:2021 – Identification and Authentication Failures",
                "CIS Control 5.3 – Disable Dormant Accounts",
            ],
            location=(
                "System → Administration → Admin and user settings → Administrators\n"
                "→ Create new admin → disable default 'admin' account"
            ),
            exploitability="High", impact_scope="Host", exposure="External",
        ))

    if len(admin_users) > 3:
        findings.append(Finding(
            severity=Severity.LOW,
            category=_S,
            title=f"Large number of administrator accounts ({len(admin_users)})",
            detail="Excessive admin accounts increase the attack surface and make access reviews harder.",
            recommendation=(
                "Review all admin accounts. Remove or demote accounts that are no longer needed. "
                "Excessive accounts expand the MITRE ATT&CK T1078 (Valid Accounts) attack surface — "
                "each unnecessary admin is a potential credential to compromise. "
                "Apply principle of least privilege (OWASP A01:2021 – Broken Access Control)."
            ),
            references=[
                "MITRE ATT&CK T1078 – Valid Accounts",
                "OWASP A01:2021 – Broken Access Control",
                "CIS Control 5.4 – Restrict Administrator Privileges to Dedicated Administrator Accounts",
            ],
            location="System → Administration → Admin and user settings → Administrators → review and remove unused accounts",
            affected=[u.get("name", "(unnamed)") for u in admin_users],
            exploitability="Medium", impact_scope="Host", exposure="Internal",
        ))

    return findings

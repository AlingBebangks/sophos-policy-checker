"""Config checks — System hardening (NTP, DNS, SNMP, updates, HA, backup, notifications)."""
from .models import Finding, Severity
from .utils import v as _v, off as _off

_S = "Config — System"


def run(cfg) -> list[Finding]:
    findings: list[Finding] = []

    # ── NTP ───────────────────────────────────────────────────────────────────
    if not cfg.ntp_servers:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="No NTP servers configured",
            detail="Without NTP, system time can drift, making log correlation and certificate validation unreliable.",
            recommendation=(
                "Configure at least two NTP servers. Use pool.ntp.org or your organisation's internal NTP. "
                "Clock skew enables MITRE ATT&CK T1557 (Adversary-in-the-Middle) via certificate replay "
                "and breaks Kerberos/log timestamps used in T1070 (Indicator Removal) detection. "
                "Aligns with CIS Control 8.4 – Standardize Time Synchronization."
            ),
            references=[
                "MITRE ATT&CK T1557 – Adversary-in-the-Middle",
                "MITRE ATT&CK T1070 – Indicator Removal",
                "CIS Control 8.4 – Standardize Time Synchronization",
                "NIST SP 800-92 §2.1 – Time Synchronization for Log Management",
            ],
            location="System → System settings → Time\n→ Add NTP server(s) → Apply",
            exploitability="Low", impact_scope="Local", exposure="Internal",
        ))
    elif len(cfg.ntp_servers) < 2:
        findings.append(Finding(
            severity=Severity.LOW,
            category=_S,
            title="Only one NTP server configured",
            detail="A single NTP source is a single point of failure for time synchronisation.",
            recommendation="Add a secondary NTP server for redundancy.",
            references=[
                "CIS Control 8.4 – Standardize Time Synchronization",
            ],
            location="System → System settings → Time\n→ Add a second NTP server → Apply",
            exploitability="Low", impact_scope="Local", exposure="Internal",
        ))

    # ── DNS ───────────────────────────────────────────────────────────────────
    dns = cfg.dns_settings
    if not dns:
        findings.append(Finding(
            severity=Severity.LOW,
            category=_S,
            title="DNS settings not found in config",
            detail="DNS configuration could not be parsed. Ensure DNS is configured and resolves correctly.",
            recommendation="Verify DNS under Network → DNS. Use trusted, internal resolvers.",
            location="Network → DNS\n→ Configure primary and secondary DNS servers",
            exploitability="Low", impact_scope="Local", exposure="Internal",
        ))
    else:
        primary   = _v(dns, "IPv4DNS1", "PrimaryDNS", "Primary", "DNSServer1")
        secondary = _v(dns, "IPv4DNS2", "SecondaryDNS", "Secondary", "DNSServer2")
        if not primary:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=_S,
                title="Primary DNS server not configured",
                detail="Without DNS the firewall cannot resolve hostnames for updates, cloud services, or threat feeds.",
                recommendation="Set a primary and secondary DNS server.",
                location="Network → DNS → Set primary and secondary resolvers → Apply",
                exploitability="Low", impact_scope="Local", exposure="Internal",
            ))
        elif not secondary:
            findings.append(Finding(
                severity=Severity.LOW,
                category=_S,
                title="No secondary DNS server configured",
                detail="A single DNS server is a single point of failure.",
                recommendation="Configure a secondary DNS server.",
                location="Network → DNS → Add secondary DNS server → Apply",
                exploitability="Low", impact_scope="Local", exposure="Internal",
            ))

        dnssec = _v(dns, "DNSSEC", "DNSSECValidation")
        if _off(dnssec):
            findings.append(Finding(
                severity=Severity.LOW,
                category=_S,
                title="DNSSEC validation not enabled",
                detail="Without DNSSEC, the firewall is vulnerable to DNS spoofing and cache poisoning attacks.",
                recommendation=(
                    "Enable DNSSEC validation in DNS settings. "
                    "DNS spoofing enables MITRE ATT&CK T1557.003 (Adversary-in-the-Middle: DHCP/DNS Spoofing) "
                    "and can redirect traffic to attacker-controlled infrastructure. "
                    "Aligns with OWASP A05:2021 – Security Misconfiguration."
                ),
                references=[
                    "MITRE ATT&CK T1557.003 – AitM: DHCP/DNS Spoofing",
                    "OWASP A05:2021 – Security Misconfiguration",
                    "RFC 9364 – DNS Security Extensions",
                ],
                location="Network → DNS → Enable DNSSEC validation → Apply",
                exploitability="Medium", impact_scope="Network", exposure="Adjacent",
            ))

    # ── SNMP ──────────────────────────────────────────────────────────────────
    snmp = cfg.snmp_settings
    if snmp:
        version = _v(snmp, "Version", "SNMPVersion", "v")
        enabled = _v(snmp, "Status", "Enable", "Enabled")
        if not _off(enabled):
            if version.lower() in ("v1", "v2", "v2c", "1", "2"):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=_S,
                    title="SNMP v1/v2c enabled — cleartext community strings",
                    detail=(
                        "SNMP v1 and v2c transmit community strings in plaintext. "
                        "An attacker on the network can capture credentials and read full device configuration."
                    ),
                    recommendation=(
                        "Disable SNMP v1/v2c. Upgrade to SNMPv3 with authentication (SHA) and encryption (AES). "
                        "SNMP v1/v2c enables MITRE ATT&CK T1040 (Network Sniffing) and "
                        "T1046 (Network Service Discovery) — the community string grants read access to the full MIB. "
                        "Aligns with OWASP A02:2021 – Cryptographic Failures."
                    ),
                    references=[
                        "MITRE ATT&CK T1040 – Network Sniffing",
                        "MITRE ATT&CK T1046 – Network Service Discovery",
                        "OWASP A02:2021 – Cryptographic Failures",
                        "CIS Control 4.5 – Implement and Manage a Firewall on End-User Devices",
                        "NIST SP 800-161 – Supply Chain Risk Management",
                        "CIS Benchmark §4.3",
                    ],
                    location="System → SNMP\n→ Set version to SNMPv3 → configure auth and privacy settings → Apply",
                    exploitability="High", impact_scope="Network", exposure="Adjacent",
                ))
            community = _v(snmp, "CommunityString", "Community", "ReadCommunity")
            if community.lower() in ("public", "private", ""):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    category=_S,
                    title="SNMP using default community string (public/private)",
                    detail="Default community strings are universally known and allow unauthenticated read or write access to device data.",
                    recommendation=(
                        "Change SNMP community strings to a long, random value or migrate to SNMPv3. "
                        "Default credentials enable MITRE ATT&CK T1078.001 (Default Accounts) — "
                        "any attacker can query the full MIB without guessing credentials. "
                        "Aligns with OWASP A07:2021 – Identification and Authentication Failures."
                    ),
                    references=[
                        "MITRE ATT&CK T1078.001 – Default Accounts",
                        "OWASP A07:2021 – Identification and Authentication Failures",
                        "CIS Control 4.2 – Establish and Maintain a Secure Configuration Process for Network Infrastructure",
                    ],
                    location="System → SNMP → Change community string → Apply",
                    exploitability="High", impact_scope="Network", exposure="Adjacent",
                ))
            allowed_hosts = _v(snmp, "AllowedHosts", "HostAllowed", "TrapServer")
            if not allowed_hosts:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=_S,
                    title="SNMP not restricted to specific management hosts",
                    detail="SNMP is enabled without an allowed-hosts restriction, making it reachable from any source.",
                    recommendation=(
                        "Restrict SNMP queries to specific management IP addresses. "
                        "Unrestricted SNMP enables MITRE ATT&CK T1046 (Network Service Discovery) "
                        "from any host on the network. "
                        "Aligns with OWASP A01:2021 – Broken Access Control."
                    ),
                    references=[
                        "MITRE ATT&CK T1046 – Network Service Discovery",
                        "OWASP A01:2021 – Broken Access Control",
                        "CIS Control 12.3 – Securely Manage Network Infrastructure",
                    ],
                    location="System → SNMP → Set Allowed Hosts → Apply",
                    exploitability="Medium", impact_scope="Network", exposure="Adjacent",
                ))

    # ── Automatic Updates ─────────────────────────────────────────────────────
    upd = cfg.update_settings
    if not upd:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="Automatic update settings not found",
            detail="Pattern updates (IPS, AV, application signatures) keep the firewall effective against new threats.",
            recommendation=(
                "Enable automatic updates for all security subscriptions. "
                "Outdated signatures enable MITRE ATT&CK T1190 (Exploit Public-Facing Application) "
                "via unpatched CVEs and T1203 (Exploitation for Client Execution). "
                "Aligns with OWASP A06:2021 – Vulnerable and Outdated Components."
            ),
            references=[
                "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                "MITRE ATT&CK T1203 – Exploitation for Client Execution",
                "OWASP A06:2021 – Vulnerable and Outdated Components",
                "CIS Control 7 – Continuous Vulnerability Management",
            ],
            location="System → Updates → Enable automatic pattern updates for IPS, AV, AppControl → Apply",
            exploitability="Low", impact_scope="Network", exposure="External",
        ))
    else:
        auto = _v(upd, "AutoUpdate", "Automatic", "Schedule", "Enable")
        if _off(auto):
            findings.append(Finding(
                severity=Severity.HIGH,
                category=_S,
                title="Automatic pattern/signature updates disabled",
                detail="Outdated IPS, AV, and application signatures reduce detection effectiveness against new threats.",
                recommendation=(
                    "Enable automatic updates. Schedule daily or more frequent updates. "
                    "Stale signatures enable MITRE ATT&CK T1190 (Exploit Public-Facing Application) "
                    "and T1036 (Masquerading) — known malware bypasses outdated AV signatures. "
                    "Aligns with OWASP A06:2021 – Vulnerable and Outdated Components."
                ),
                references=[
                    "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                    "MITRE ATT&CK T1036 – Masquerading",
                    "OWASP A06:2021 – Vulnerable and Outdated Components",
                    "CIS Control 7.3 – Perform Automated Patch Management",
                    "CIS Sophos Benchmark §3.2",
                ],
                location="System → Updates → Enable automatic updates → set frequency to Daily → Apply",
                exploitability="Medium", impact_scope="Network", exposure="External",
            ))
        else:
            # CIS 3.2: interval should be every 15 minutes
            interval = _v(upd, "Interval", "UpdateInterval", "Frequency", "CheckInterval")
            try:
                interval_min = int(interval)
                if interval_min > 15:
                    findings.append(Finding(
                        severity=Severity.LOW,
                        category=_S,
                        title=f"CIS 3.2 – Pattern update interval is {interval_min} min (should be ≤15 min)",
                        detail=(
                            f"Pattern updates are set to every {interval_min} minutes. "
                            "The CIS Sophos Benchmark requires updates every 15 minutes to "
                            "minimise the window of vulnerability to newly released threats."
                        ),
                        recommendation=(
                            "Set the pattern update interval to 'Every 15 minutes' under "
                            "System → Backup & Firmware → Pattern Updates. "
                            "Aligns with CIS Sophos Benchmark §3.2."
                        ),
                        references=[
                            "CIS Sophos Benchmark §3.2",
                            "CIS Control 7.3 – Perform Automated Patch Management",
                        ],
                        location=(
                            "System → Backup & Firmware → Pattern Updates\n"
                            "→ Interval → Every 15 minutes → Apply"
                        ),
                        exploitability="Low", impact_scope="Network", exposure="External",
                    ))
            except (ValueError, TypeError):
                pass

    # ── CIS 3.3 – Hotfix auto-install ────────────────────────────────────────
    # Hotfix status is typically only visible via CLI; check raw config for hints
    hotfix_el = None
    for key in ("Hotfix", "HotfixSettings", "AutoHotfix", "HotfixInstall"):
        if key in cfg.raw_sections:
            hotfix_el = cfg.system_settings.get(key) or cfg.update_settings.get(key)
            if hotfix_el:
                break
    if not hotfix_el:
        hotfix_val = _v(cfg.system_settings, "Hotfix", "HotfixEnabled", "AllowHotfix")
        if not hotfix_val:
            hotfix_val = _v(cfg.update_settings, "Hotfix", "HotfixEnabled", "AllowHotfix")
        if hotfix_val and _off(hotfix_val):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=_S,
                title="CIS 3.3 – Hotfix auto-installation is disabled",
                detail=(
                    "Automatic hotfix installation is disabled. Security hotfixes address "
                    "critical vulnerabilities and should be applied automatically to minimise "
                    "exposure time to known firewall vulnerabilities."
                ),
                recommendation=(
                    "Enable automatic hotfix installation via CLI: "
                    "Select Option 4 > system hotfix show, then enable. "
                    "Aligns with CIS Sophos Benchmark §3.3."
                ),
                references=[
                    "CIS Sophos Benchmark §3.3",
                    "CIS Control 7.3 – Perform Automated Patch Management",
                    "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                ],
                location=(
                    "Sophos CLI: Select Option 4 > Advanced Shell\n"
                    "> system hotfix enable"
                ),
                exploitability="Medium", impact_scope="Network", exposure="External",
            ))

    # ── CIS 3.5 – No expired subscriptions ───────────────────────────────────
    lic = cfg.licensing_settings
    if lic:
        expired: list[str] = []
        for key, val in lic.items() if isinstance(lic, dict) else []:
            if isinstance(val, str) and val.lower() in ("expired", "inactive", "deactivated"):
                expired.append(key)
            elif isinstance(val, dict):
                status_val = _v(val, "Status", "State", "LicenseStatus")
                if status_val.lower() in ("expired", "inactive", "deactivated"):
                    expired.append(key)
        if expired:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=_S,
                title=f"CIS 3.5 – Expired subscription licenses detected: {', '.join(expired[:5])}",
                detail=(
                    "One or more subscription licenses are expired. Expired subscriptions stop "
                    "receiving security signature updates, making the corresponding protection "
                    "features ineffective against new threats."
                ),
                recommendation=(
                    "Renew all expired subscriptions immediately under "
                    "System → Administration → Licensing → Synchronize. "
                    "Aligns with CIS Sophos Benchmark §3.5."
                ),
                references=[
                    "CIS Sophos Benchmark §3.5",
                    "CIS Control 12.1 – Ensure Network Infrastructure is Up-to-Date",
                    "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                ],
                location=(
                    "System → Administration → Licensing\n"
                    "→ Synchronize → contact Sophos to renew expired modules"
                ),
                affected=expired,
                exploitability="Medium", impact_scope="Network", exposure="External",
            ))

    # ── Backup ────────────────────────────────────────────────────────────────
    backup = cfg.backup_settings
    if not backup:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="Automated backup not configured",
            detail="Without automated backups, a hardware failure or misconfiguration could result in permanent loss of firewall configuration.",
            recommendation=(
                "Configure scheduled encrypted backups to a remote location (FTP, email, or cloud). "
                "Lack of backups means ransomware (MITRE ATT&CK T1486 – Data Encrypted for Impact) "
                "targeting the device cannot be recovered without rebuilding from scratch. "
                "Aligns with OWASP A05:2021 – Security Misconfiguration."
            ),
            references=[
                "MITRE ATT&CK T1486 – Data Encrypted for Impact",
                "OWASP A05:2021 – Security Misconfiguration",
                "CIS Control 11 – Data Recovery",
            ],
            location="System → Backup & firmware → Backup\n→ Configure scheduled backup with encryption → Save",
            exploitability="Low", impact_scope="Local", exposure="Internal",
        ))
    else:
        schedule = _v(backup, "Schedule", "BackupSchedule", "AutoBackup", "Frequency")
        if _off(schedule):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=_S,
                title="Scheduled backups disabled",
                detail="Manual-only backups are often forgotten, leaving the device unprotected against configuration loss.",
                recommendation=(
                    "Enable scheduled automated backups — daily or weekly at minimum. "
                    "Aligns with CIS Control 11 – Data Recovery."
                ),
                references=[
                    "CIS Control 11 – Data Recovery",
                    "MITRE ATT&CK T1486 – Data Encrypted for Impact",
                ],
                location="System → Backup & firmware → Backup → Enable scheduled backup → Apply",
                exploitability="Low", impact_scope="Local", exposure="Internal",
            ))
        # Mode: should be Mail (email) or FTP — not Manual-only
        mode = _v(backup, "BackupMode", "Mode", "BackupType", "DeliveryMethod")
        if mode and mode.lower() in ("manual", "local", ""):
            findings.append(Finding(
                severity=Severity.LOW,
                category=_S,
                title="Backup delivery mode is manual/local only",
                detail=(
                    "Backup mode is set to manual or local storage only. "
                    "Manual backups are frequently forgotten, and local-only backups are lost if the "
                    "device fails. The Sophos official audit baseline expects backup mode 'Mail' so a "
                    "copy is sent off-device automatically."
                ),
                recommendation=(
                    "Set backup mode to 'Mail' (email) or 'FTP' so backups are sent off-device "
                    "automatically. Configure the destination address/server and a backup schedule. "
                    "Aligns with CIS Control 11.2 – Perform Automated Backups."
                ),
                references=[
                    "CIS Control 11.2 – Perform Automated Backups",
                    "MITRE ATT&CK T1486 – Data Encrypted for Impact",
                ],
                location=(
                    "System → Backup & firmware → Backup\n"
                    "→ Backup mode → select 'Mail' or 'FTP' → configure destination → Apply"
                ),
                exploitability="Low", impact_scope="Local", exposure="Internal",
            ))

        # Recipient / destination must be set
        recipient = _v(backup, "EmailAddress", "Recipient", "FTPServer", "BackupEmail", "Destination")
        if not recipient:
            findings.append(Finding(
                severity=Severity.LOW,
                category=_S,
                title="Backup destination address/server not configured",
                detail=(
                    "A backup schedule exists but no email address or FTP server is configured as the "
                    "destination. Backups will not be sent off-device, making them equivalent to no backup."
                ),
                recommendation=(
                    "Set a backup email recipient or FTP server address. "
                    "Aligns with CIS Control 11.2 – Perform Automated Backups."
                ),
                references=["CIS Control 11.2 – Perform Automated Backups"],
                location=(
                    "System → Backup & firmware → Backup\n"
                    "→ Enter email address or FTP server → Apply"
                ),
                exploitability="Low", impact_scope="Local", exposure="Internal",
            ))

        # Frequency
        freq = _v(backup, "BackupFrequency", "Frequency", "Schedule", "BackupSchedule")
        if freq and freq.lower() in ("never", "manual", "none", "disable", "disabled"):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=_S,
                title="Backup frequency is set to never / disabled",
                detail="A backup destination is configured but the frequency is set so backups never run automatically.",
                recommendation=(
                    "Set backup frequency to Weekly at minimum; Daily is preferred for production firewalls. "
                    "Aligns with CIS Control 11.2 – Perform Automated Backups."
                ),
                references=["CIS Control 11.2 – Perform Automated Backups"],
                location=(
                    "System → Backup & firmware → Backup\n"
                    "→ Frequency → select Weekly or Daily → Apply"
                ),
                exploitability="Low", impact_scope="Local", exposure="Internal",
            ))

        encrypt = _v(backup, "EncryptionPassword", "Encrypt", "Encryption")
        if not encrypt or _off(encrypt):
            findings.append(Finding(
                severity=Severity.LOW,
                category=_S,
                title="Backup encryption not configured",
                detail="Unencrypted backups expose full device configuration including VPN pre-shared keys, SNMP community strings, and admin credentials.",
                recommendation=(
                    "Set an encryption password for all configuration backups. "
                    "Unencrypted backups enable MITRE ATT&CK T1552 (Unsecured Credentials) — "
                    "anyone with access to the backup file gets all credentials. "
                    "Aligns with OWASP A02:2021 – Cryptographic Failures."
                ),
                references=[
                    "MITRE ATT&CK T1552 – Unsecured Credentials",
                    "OWASP A02:2021 – Cryptographic Failures",
                    "CIS Control 11.3 – Establish and Maintain a Data Recovery Process",
                ],
                location="System → Backup & firmware → Backup → Set encryption password → Apply",
                exploitability="Low", impact_scope="Local", exposure="Internal",
            ))

    # ── Notifications ─────────────────────────────────────────────────────────
    notif = cfg.notification_settings
    if not notif:
        findings.append(Finding(
            severity=Severity.LOW,
            category=_S,
            title="Notification/alerting settings not found",
            detail="Without alert notifications, critical events (HA failover, high CPU, attack detection) go unnoticed.",
            recommendation=(
                "Configure email notifications for critical system events. "
                "Lack of alerting supports MITRE ATT&CK T1562 (Impair Defenses) — "
                "attackers rely on defenders not being notified. "
                "Aligns with OWASP A09:2021 – Security Logging and Monitoring Failures."
            ),
            references=[
                "MITRE ATT&CK T1562 – Impair Defenses",
                "OWASP A09:2021 – Security Logging and Monitoring Failures",
                "CIS Control 8.11 – Conduct Audit Log Reviews",
            ],
            location="System → Administration → Notification settings → Configure email alerts → Apply",
            exploitability="Low", impact_scope="Local", exposure="Internal",
        ))
    else:
        # ── Notification event toggle audit (mirrors Sophos official audit tool) ──
        # These are the critical alert categories that should have email enabled.
        _CRITICAL_ALERTS = [
            ("FirmwareReadyEmail",       "Firmware update ready"),
            ("FirmwareInstalledEmail",   "Firmware installed"),
            ("FirmwareInstalledFailedEmail", "Firmware installation failed"),
            ("IPSSigFailEmail",          "IPS signature update failure"),
            ("AVFailEmail",              "Antivirus engine failure"),
            ("RedDownEmail",             "RED tunnel down"),
            ("ApplianceUnpluggedEmail",  "Appliance unplugged / power loss"),
            ("ConfDiskExdEmail",         "Config disk space exceeded"),
            ("SigDiskExdEmail",          "Signature disk space exceeded"),
        ]
        # Retrieve the notification list — some firmware nests it under NotificationList
        notif_list = cfg.notification_settings
        if isinstance(notif_list, dict):
            notif_list = notif_list.get("NotificationList", notif_list)

        disabled_alerts: list[str] = []
        if isinstance(notif_list, dict):
            for key, label in _CRITICAL_ALERTS:
                val = str(notif_list.get(key, "")).lower()
                if val in ("disable", "disabled", "0", "false", "off", ""):
                    disabled_alerts.append(label)

        if disabled_alerts:
            findings.append(Finding(
                severity=Severity.LOW,
                category=_S,
                title="Critical notification alerts are not enabled",
                detail=(
                    "The following critical event notifications do not have email alerting enabled: "
                    + ", ".join(disabled_alerts) + ". "
                    "Without these alerts, firmware failures, IPS/AV update failures, and connectivity "
                    "losses go unnoticed until the next manual check."
                ),
                recommendation=(
                    "Enable email notifications for all critical system events under "
                    "System → Administration → Notification list. "
                    "At minimum: firmware events, IPS/AV signature failures, RED tunnel status, "
                    "appliance power/connectivity, and disk space alerts. "
                    "Aligns with OWASP A09:2021 – Security Logging and Monitoring Failures and "
                    "CIS Control 8.11 – Conduct Audit Log Reviews."
                ),
                references=[
                    "OWASP A09:2021 – Security Logging and Monitoring Failures",
                    "CIS Control 8.11 – Conduct Audit Log Reviews",
                    "MITRE ATT&CK T1562 – Impair Defenses",
                ],
                location=(
                    "System → Administration → Notification list\n"
                    "→ Enable email for: " + ", ".join(disabled_alerts[:4])
                    + (" and more" if len(disabled_alerts) > 4 else "") + " → Apply"
                ),
                affected=disabled_alerts,
                exploitability="Low", impact_scope="Local", exposure="Internal",
            ))

    # ── Sophos Central / Central Management ──────────────────────────────────
    cm = cfg.central_mgmt
    if not cm:
        findings.append(Finding(
            severity=Severity.LOW,
            category=_S,
            title="Sophos Central management not detected",
            detail=(
                "No central management configuration was found. The firewall appears to be "
                "managed locally only. Standalone-managed firewalls have no centralised change "
                "tracking, no enforced policy baseline, and no cross-device visibility — "
                "changes can be made without a review process."
            ),
            recommendation=(
                "Connect the firewall to Sophos Central for centralised management, policy enforcement, "
                "firmware management, and audit logging. Central management ensures all changes "
                "are logged and attributed. Without it, MITRE ATT&CK T1562.004 "
                "(Impair Defenses: Disable or Modify System Firewall) changes may go undetected "
                "with no central audit trail. "
                "Aligns with CIS Control 4.1 – Establish and Maintain a Secure Configuration Process."
            ),
            references=[
                "MITRE ATT&CK T1562.004 – Impair Defenses: Disable or Modify System Firewall",
                "CIS Control 4.1 – Establish and Maintain a Secure Configuration Process",
                "OWASP A05:2021 – Security Misconfiguration",
            ],
            location=(
                "System → Sophos Central\n"
                "→ Register the firewall to your Sophos Central account → Apply"
            ),
            exploitability="Low", impact_scope="Local", exposure="Internal",
        ))
    else:
        status = _v(cm, "Status", "Enable", "Connected", "Registered")
        if _off(status):
            findings.append(Finding(
                severity=Severity.LOW,
                category=_S,
                title="Sophos Central management is disconnected",
                detail=(
                    "A Sophos Central configuration block was found but the device is not connected "
                    "or registration is disabled. Policy enforcement and audit logging from central "
                    "management are not active."
                ),
                recommendation=(
                    "Reconnect the firewall to Sophos Central and confirm registration status. "
                    "Aligns with CIS Control 4.1 – Establish and Maintain a Secure Configuration Process."
                ),
                references=[
                    "CIS Control 4.1 – Establish and Maintain a Secure Configuration Process",
                    "MITRE ATT&CK T1562.004 – Impair Defenses: Disable or Modify System Firewall",
                ],
                location="System → Sophos Central → Reconnect / re-register → Apply",
                exploitability="Low", impact_scope="Local", exposure="Internal",
            ))
        else:
            findings.append(Finding(
                severity=Severity.INFO,
                category=_S,
                title="Sophos Central management is active",
                detail=(
                    "The firewall is registered with and managed by Sophos Central. "
                    "Centralised change tracking, policy enforcement, and cross-device visibility are available."
                ),
                recommendation="Verify that policy baselines and firmware management are configured in Sophos Central.",
                exploitability="Low", impact_scope="Local", exposure="Internal",
            ))

    # ── CIS 3.1 / HA ─────────────────────────────────────────────────────────
    ha = cfg.ha_settings
    if ha:
        mode = _v(ha, "Mode", "HAMode", "State", "Status")
        if mode.lower() in ("standalone", "disable", "disabled", "off", ""):
            findings.append(Finding(
                severity=Severity.INFO,
                category=_S,
                title="CIS 3.1 – High Availability not configured (standalone mode)",
                detail="The firewall is running in standalone mode. A hardware failure will cause a network outage.",
                recommendation=(
                    "Consider HA Active-Passive or Active-Active deployment for critical environments. "
                    "Aligns with CIS Sophos Benchmark §3.1."
                ),
                references=["CIS Sophos Benchmark §3.1"],
                location="System → High availability → Configure HA peer → Apply",
                exploitability="Low", impact_scope="Local", exposure="Internal",
            ))
        else:
            # Check for Fully Synchronized state (CIS 3.1 specifically requires this)
            ha_status = _v(ha, "HAStatus", "PeerStatus", "SyncStatus", "ClusterStatus")
            if ha_status and ha_status.lower() in ("faulty", "standalone", "notsynced",
                                                    "not_synced", "unsynchronized"):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=_S,
                    title="CIS 3.1 – HA peer is not in 'Fully Synchronized' state",
                    detail=(
                        f"HA status is '{ha_status}'. The CIS benchmark requires the HA peer "
                        "to show 'Established[Active-Passive]' or 'Established[Active-Active]' "
                        "with both Local and Peer devices synchronized. A faulty or standalone "
                        "auxiliary node means failover protection is not available."
                    ),
                    recommendation=(
                        "Navigate to Configure → System Services → High Availability and "
                        "resolve the sync issue. Re-configure HA if the auxiliary is showing Faulty. "
                        "Aligns with CIS Sophos Benchmark §3.1."
                    ),
                    references=[
                        "CIS Sophos Benchmark §3.1",
                        "OWASP A05:2021 – Security Misconfiguration",
                    ],
                    location="Configure → System Services → High Availability → High Availability Status",
                    exploitability="Low", impact_scope="Local", exposure="Internal",
                ))
            sync = _v(ha, "ConfigSync", "SynchroniseConfig", "Sync")
            if _off(sync):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=_S,
                    title="CIS 3.1 – HA configuration synchronisation disabled",
                    detail="HA peers with out-of-sync configs can apply different policies after failover.",
                    recommendation=(
                        "Enable configuration synchronisation between HA peers. "
                        "Desynchronised HA nodes may have weaker policies on the standby unit, "
                        "enabling MITRE ATT&CK T1562.004 (Disable or Modify System Firewall) by circumstance. "
                        "Aligns with CIS Sophos Benchmark §3.1 and OWASP A05:2021."
                    ),
                    references=[
                        "CIS Sophos Benchmark §3.1",
                        "MITRE ATT&CK T1562.004 – Impair Defenses: Disable or Modify System Firewall",
                        "OWASP A05:2021 – Security Misconfiguration",
                    ],
                    location="System → High availability → Enable Config sync → Apply",
                    exploitability="Low", impact_scope="Local", exposure="Internal",
                ))

    return findings

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
            ))
        elif not secondary:
            findings.append(Finding(
                severity=Severity.LOW,
                category=_S,
                title="No secondary DNS server configured",
                detail="A single DNS server is a single point of failure.",
                recommendation="Configure a secondary DNS server.",
                location="Network → DNS → Add secondary DNS server → Apply",
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
                ],
                location="System → Updates → Enable automatic updates → set frequency to Daily → Apply",
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
        ))

    # ── HA ────────────────────────────────────────────────────────────────────
    ha = cfg.ha_settings
    if ha:
        mode = _v(ha, "Mode", "HAMode", "State")
        if mode.lower() in ("standalone", "disable", "disabled", "off", ""):
            findings.append(Finding(
                severity=Severity.INFO,
                category=_S,
                title="High Availability not configured",
                detail="The firewall is running in standalone mode. A hardware failure will cause a network outage.",
                recommendation="Consider HA Active-Passive or Active-Active deployment for critical environments.",
                location="System → High availability → Configure HA peer → Apply",
            ))
        else:
            sync = _v(ha, "ConfigSync", "SynchroniseConfig", "Sync")
            if _off(sync):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=_S,
                    title="HA configuration synchronisation disabled",
                    detail="HA peers with out-of-sync configs can apply different policies after failover.",
                    recommendation=(
                        "Enable configuration synchronisation between HA peers. "
                        "Desynchronised HA nodes may have weaker policies on the standby unit, "
                        "enabling MITRE ATT&CK T1562.004 (Disable or Modify System Firewall) by circumstance. "
                        "Aligns with OWASP A05:2021 – Security Misconfiguration."
                    ),
                    references=[
                        "MITRE ATT&CK T1562.004 – Impair Defenses: Disable or Modify System Firewall",
                        "OWASP A05:2021 – Security Misconfiguration",
                    ],
                    location="System → High availability → Enable Config sync → Apply",
                ))

    return findings

"""Config checks — System hardening (NTP, DNS, SNMP, updates, HA, backup, notifications)."""
from .models import Finding, Severity

_S = "Config — System"


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

    # ── NTP ───────────────────────────────────────────────────────────────────
    if not cfg.ntp_servers:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=_S,
            title="No NTP servers configured",
            detail="Without NTP, system time can drift, making log correlation and certificate validation unreliable.",
            recommendation="Configure at least two NTP servers. Use pool.ntp.org or your organisation's internal NTP.",
            location="System → System settings → Time\n→ Add NTP server(s) → Apply",
        ))
    elif len(cfg.ntp_servers) < 2:
        findings.append(Finding(
            severity=Severity.LOW,
            category=_S,
            title="Only one NTP server configured",
            detail="A single NTP source is a single point of failure for time synchronisation.",
            recommendation="Add a secondary NTP server for redundancy.",
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
                recommendation="Enable DNSSEC validation in DNS settings.",
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
                        "An attacker on the same network segment can capture credentials and read device configuration."
                    ),
                    recommendation="Disable SNMP v1/v2c. Upgrade to SNMPv3 with authentication (SHA) and encryption (AES).",
                    location="System → SNMP\n→ Set version to SNMPv3 → configure auth and privacy settings → Apply",
                    references=["CIS Benchmark §4.3", "NIST SP 800-161"],
                ))
            community = _v(snmp, "CommunityString", "Community", "ReadCommunity")
            if community.lower() in ("public", "private", ""):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    category=_S,
                    title="SNMP using default community string (public/private)",
                    detail="Default community strings are universally known and allow unauthenticated read or write access to device data.",
                    recommendation="Change SNMP community strings to a long, random value or migrate to SNMPv3.",
                    location="System → SNMP → Change community string → Apply",
                ))
            allowed_hosts = _v(snmp, "AllowedHosts", "HostAllowed", "TrapServer")
            if not allowed_hosts:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=_S,
                    title="SNMP not restricted to specific management hosts",
                    detail="SNMP is enabled without an allowed-hosts restriction, making it reachable from any source.",
                    recommendation="Restrict SNMP queries to specific management IP addresses.",
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
            recommendation="Enable automatic updates for all security subscriptions.",
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
                recommendation="Enable automatic updates. Schedule daily or more frequent updates.",
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
            recommendation="Configure scheduled encrypted backups to a remote location (FTP, email, or cloud).",
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
                recommendation="Enable scheduled automated backups — daily or weekly at minimum.",
                location="System → Backup & firmware → Backup → Enable scheduled backup → Apply",
            ))
        encrypt = _v(backup, "EncryptionPassword", "Encrypt", "Encryption")
        if not encrypt or _off(encrypt):
            findings.append(Finding(
                severity=Severity.LOW,
                category=_S,
                title="Backup encryption not configured",
                detail="Unencrypted backups expose full device configuration including VPN keys and credentials.",
                recommendation="Set an encryption password for all configuration backups.",
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
            recommendation="Configure email notifications for critical system events.",
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
                    recommendation="Enable configuration synchronisation between HA peers.",
                    location="System → High availability → Enable Config sync → Apply",
                ))

    return findings

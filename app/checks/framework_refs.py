"""Centralized NIST SP 800-53 Rev 5 and CIS Controls v8 reference enrichment.

Maps each finding category (and optionally severity) to the relevant
NIST and CIS control identifiers. Called by engine.py after all checks
run so every finding gets consistent framework alignment without
duplicating reference lists in each check module.

References are *appended* (not replaced) so module-specific references
like RFCs and CVEs are preserved.
"""
from .models import Finding, Severity


# ── Per-category mappings ────────────────────────────────────────────────────
# Each entry: list of reference strings to append to Finding.references.
# Ordered: NIST SP 800-53 Rev 5 controls first, then CIS Controls v8.

_CATEGORY_REFS: dict[str, list[str]] = {

    "Firewall Rules": [
        # NIST SP 800-53 Rev 5
        "NIST SP 800-53 Rev 5 AC-4 – Information Flow Enforcement",
        "NIST SP 800-53 Rev 5 CM-7 – Least Functionality",
        "NIST SP 800-53 Rev 5 SC-7 – Boundary Protection",
        "NIST SP 800-53 Rev 5 SC-7(5) – Deny by Default / Allow by Exception",
        "NIST SP 800-41 Rev 1 – Guidelines on Firewalls and Firewall Policy",
        # CIS Controls v8
        "CIS Controls v8 – 4.4 Implement and Manage a Firewall on Servers",
        "CIS Controls v8 – 12.1 Ensure Network Infrastructure is Up-to-Date",
        "CIS Controls v8 – 13.1 Centralize Security Event Alerting",
        "CIS Benchmark – Sophos XG Firewall",
    ],

    "NAT Rules": [
        "NIST SP 800-53 Rev 5 AC-4 – Information Flow Enforcement",
        "NIST SP 800-53 Rev 5 CM-7 – Least Functionality",
        "NIST SP 800-53 Rev 5 SC-7 – Boundary Protection",
        "NIST SP 800-53 Rev 5 SC-7(8) – Route Traffic to Authenticated Proxy Servers",
        "NIST SP 800-41 Rev 1 §3.3 – NAT Considerations",
        "CIS Controls v8 – 4.4 Implement and Manage a Firewall on Servers",
        "CIS Controls v8 – 12.1 Ensure Network Infrastructure is Up-to-Date",
    ],

    "VPN — IPSec": [
        "NIST SP 800-53 Rev 5 SC-8 – Transmission Confidentiality and Integrity",
        "NIST SP 800-53 Rev 5 SC-8(1) – Cryptographic Protection",
        "NIST SP 800-53 Rev 5 SC-12 – Cryptographic Key Establishment and Management",
        "NIST SP 800-53 Rev 5 SC-13 – Cryptographic Protection",
        "NIST SP 800-53 Rev 5 IA-3 – Device Identification and Authentication",
        "NIST SP 800-77 Rev 1 – Guide to IPsec VPNs",
        "NIST SP 800-131A Rev 2 – Transitioning to Stronger Cryptographic Algorithms",
        "CIS Controls v8 – 3.10 Encrypt Sensitive Data in Transit",
        "CIS Controls v8 – 12.6 Use of Secure Network Management and Communication Protocols",
    ],

    "Administration": [
        "NIST SP 800-53 Rev 5 AC-2 – Account Management",
        "NIST SP 800-53 Rev 5 AC-17 – Remote Access",
        "NIST SP 800-53 Rev 5 AC-17(2) – Remote Access / Protection of Confidentiality Using Encryption",
        "NIST SP 800-53 Rev 5 CM-6 – Configuration Settings",
        "NIST SP 800-53 Rev 5 IA-2 – Identification and Authentication (Organizational Users)",
        "NIST SP 800-53 Rev 5 IA-2(1) – MFA for Privileged Accounts",
        "NIST SP 800-53 Rev 5 IA-5 – Authenticator Management",
        "NIST SP 800-53 Rev 5 SI-4(23) – Host-Based Devices",
        "CIS Controls v8 – 4.6 Securely Manage Enterprise Assets and Software Remotely",
        "CIS Controls v8 – 5.3 Disable Dormant Accounts",
        "CIS Controls v8 – 6.3 Require MFA for Externally-Exposed Applications",
        "CIS Controls v8 – 6.5 Require MFA for Administrative Access",
    ],

    "Logging": [
        "NIST SP 800-53 Rev 5 AU-2 – Event Logging",
        "NIST SP 800-53 Rev 5 AU-3 – Content of Audit Records",
        "NIST SP 800-53 Rev 5 AU-6 – Audit Record Review, Analysis, and Reporting",
        "NIST SP 800-53 Rev 5 AU-9 – Protection of Audit Information",
        "NIST SP 800-53 Rev 5 AU-12 – Audit Record Generation",
        "NIST SP 800-53 Rev 5 SI-4 – System Monitoring",
        "NIST SP 800-92 – Guide to Computer Security Log Management",
        "CIS Controls v8 – 8.2 Collect Audit Logs",
        "CIS Controls v8 – 8.5 Collect Detailed Audit Logs",
        "CIS Controls v8 – 8.9 Centralize Audit Logs",
        "CIS Controls v8 – 13.1 Centralize Security Event Alerting",
        "CIS Controls v8 – 13.3 Deploy a Network Intrusion Detection Solution",
        "CIS Controls v8 – 13.6 Collect Network Traffic Flow Logs",
    ],

    "Config — System": [
        "NIST SP 800-53 Rev 5 CM-2 – Baseline Configuration",
        "NIST SP 800-53 Rev 5 CM-6 – Configuration Settings",
        "NIST SP 800-53 Rev 5 CM-7 – Least Functionality",
        "NIST SP 800-53 Rev 5 SI-2 – Flaw Remediation",
        "NIST SP 800-53 Rev 5 SI-2(2) – Automated Flaw Remediation Status",
        "NIST SP 800-53 Rev 5 CP-9 – System Backup",
        "NIST SP 800-53 Rev 5 SC-45 – System Time Synchronization",
        "NIST SP 800-53 Rev 5 MA-4 – Nonlocal Maintenance",
        "NIST CSF v2.0 – PR.IP-1 (Baseline Configuration Maintained)",
        "CIS Controls v8 – 4.1 Establish and Maintain a Secure Configuration Process",
        "CIS Controls v8 – 4.2 Establish and Maintain a Secure Configuration Process for Network Infrastructure",
        "CIS Controls v8 – 7.3 Perform Automated Operating System Patch Management",
        "CIS Controls v8 – 8.4 Standardize Time Synchronization",
        "CIS Controls v8 – 11.2 Perform Automated Backups",
        "CIS Controls v8 – 11.3 Protect Recovery Data",
    ],

    "Config — Authentication": [
        "NIST SP 800-53 Rev 5 AC-2 – Account Management",
        "NIST SP 800-53 Rev 5 AC-3 – Access Enforcement",
        "NIST SP 800-53 Rev 5 IA-2 – Identification and Authentication",
        "NIST SP 800-53 Rev 5 IA-2(1) – MFA for Privileged Accounts",
        "NIST SP 800-53 Rev 5 IA-2(2) – MFA for Non-Privileged Accounts",
        "NIST SP 800-53 Rev 5 IA-5 – Authenticator Management",
        "NIST SP 800-53 Rev 5 IA-5(1) – Password-Based Authentication",
        "NIST SP 800-53 Rev 5 IA-8 – Identification and Authentication (Non-Org Users)",
        "NIST SP 800-53 Rev 5 AC-7 – Unsuccessful Logon Attempts",
        "NIST SP 800-63B – Digital Identity Guidelines: Authentication",
        "CIS Controls v8 – 5.1 Establish and Maintain an Inventory of Accounts",
        "CIS Controls v8 – 5.2 Use Unique Passwords",
        "CIS Controls v8 – 5.3 Disable Dormant Accounts",
        "CIS Controls v8 – 5.4 Restrict Administrator Privileges to Dedicated Accounts",
        "CIS Controls v8 – 6.2 Establish an Access Granting Process",
        "CIS Controls v8 – 6.3 Require MFA for Externally-Exposed Applications",
        "CIS Controls v8 – 6.5 Require MFA for Administrative Access",
    ],

    "Config — Certificates": [
        "NIST SP 800-53 Rev 5 IA-3 – Device Identification and Authentication",
        "NIST SP 800-53 Rev 5 SC-12 – Cryptographic Key Establishment and Management",
        "NIST SP 800-53 Rev 5 SC-13 – Cryptographic Protection",
        "NIST SP 800-53 Rev 5 SC-17 – Public Key Infrastructure Certificates",
        "NIST SP 800-53 Rev 5 SC-8(1) – Cryptographic Protection in Transit",
        "NIST SP 800-57 Part 1 Rev 5 – Key Management Recommendations",
        "NIST SP 800-131A Rev 2 – Transitioning to Stronger Cryptographic Algorithms",
        "CIS Controls v8 – 3.10 Encrypt Sensitive Data in Transit",
        "CIS Controls v8 – 4.2 Establish and Maintain a Secure Configuration Process for Network Infrastructure",
    ],

    "Config — Network": [
        "NIST SP 800-53 Rev 5 AC-4 – Information Flow Enforcement",
        "NIST SP 800-53 Rev 5 CM-7 – Least Functionality",
        "NIST SP 800-53 Rev 5 SC-7 – Boundary Protection",
        "NIST SP 800-53 Rev 5 SC-7(5) – Deny by Default / Allow by Exception",
        "NIST SP 800-53 Rev 5 SC-7(21) – Isolation of System Components",
        "NIST SP 800-53 Rev 5 SI-10 – Information Input Validation",
        "NIST SP 800-41 Rev 1 – Guidelines on Firewalls and Firewall Policy",
        "NIST SP 800-119 – Guidelines for the Secure Deployment of IPv6",
        "CIS Controls v8 – 12.1 Ensure Network Infrastructure is Up-to-Date",
        "CIS Controls v8 – 12.2 Establish and Maintain a Secure Network Architecture",
        "CIS Controls v8 – 12.7 Ensure Remote Devices Use a VPN",
        "CIS Controls v8 – 13.4 Perform Traffic Filtering Between Network Segments",
    ],

    "Config — Threat Protection": [
        "NIST SP 800-53 Rev 5 RA-5 – Vulnerability Monitoring and Scanning",
        "NIST SP 800-53 Rev 5 SI-2 – Flaw Remediation",
        "NIST SP 800-53 Rev 5 SI-3 – Malicious Code Protection",
        "NIST SP 800-53 Rev 5 SI-3(2) – Automatic Updates",
        "NIST SP 800-53 Rev 5 SI-4 – System Monitoring",
        "NIST SP 800-53 Rev 5 SI-4(4) – Inbound and Outbound Communications Traffic",
        "NIST SP 800-94 – Guide to Intrusion Detection and Prevention Systems",
        "NIST CSF v2.0 – DE.CM-1 (Networks are Monitored to Detect Attacks)",
        "CIS Controls v8 – 7.5 Perform Automated Vulnerability Scans of Internal Enterprise Assets",
        "CIS Controls v8 – 9.3 Maintain and Enforce Network-Based URL Filters",
        "CIS Controls v8 – 10.1 Deploy and Maintain Anti-Malware Software",
        "CIS Controls v8 – 10.2 Configure Automatic Anti-Malware Signature Updates",
        "CIS Controls v8 – 13.3 Deploy a Network Intrusion Detection Solution",
        "CIS Controls v8 – 13.7 Deploy a Host-Based Intrusion Detection Solution",
    ],

    "Config — Email & SMTP": [
        "NIST SP 800-53 Rev 5 SC-8 – Transmission Confidentiality and Integrity",
        "NIST SP 800-53 Rev 5 SC-8(1) – Cryptographic Protection",
        "NIST SP 800-53 Rev 5 SI-8 – Spam Protection",
        "NIST SP 800-53 Rev 5 SI-10 – Information Input Validation",
        "NIST SP 800-177 Rev 1 – Trustworthy Email",
        "NIST SP 800-177 Rev 1 §4.5 – DKIM", "NIST SP 800-177 Rev 1 §4.6 – SPF",
        "NIST SP 800-177 Rev 1 §4.7 – DMARC",
        "CIS Controls v8 – 9.1 Ensure Use of Only Fully Supported Browsers and Email Clients",
        "CIS Controls v8 – 9.5 Implement DMARC and Enable Receiver-Side Verification",
        "CIS Controls v8 – 9.6 Block Unnecessary File Types",
        "CIS Controls v8 – 10.1 Deploy and Maintain Anti-Malware Software",
    ],

    "Config — Port Exposure": [
        "NIST SP 800-53 Rev 5 AC-4 – Information Flow Enforcement",
        "NIST SP 800-53 Rev 5 CM-7 – Least Functionality (permit only required ports)",
        "NIST SP 800-53 Rev 5 CM-7(1) – Periodic Review of Unnecessary Functions",
        "NIST SP 800-53 Rev 5 RA-3 – Risk Assessment",
        "NIST SP 800-53 Rev 5 SC-7 – Boundary Protection",
        "NIST SP 800-53 Rev 5 SC-7(5) – Deny by Default / Allow by Exception",
        "NIST SP 800-41 Rev 1 §3.1 – Least-Privilege Firewall Rules",
        "NIST CSF v2.0 – PR.AC-3 (Remote Access is Managed)",
        "CIS Controls v8 – 4.4 Implement and Manage a Firewall on Servers",
        "CIS Controls v8 – 4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets",
        "CIS Controls v8 – 12.1 Ensure Network Infrastructure is Up-to-Date",
        "CIS Controls v8 – 18.1 Establish and Maintain a Penetration Testing Program",
    ],
}

# ── Severity-level additions ──────────────────────────────────────────────────
# Critical/High findings additionally reference incident-response controls.
_SEVERITY_EXTRA: dict[Severity, list[str]] = {
    Severity.CRITICAL: [
        "NIST SP 800-53 Rev 5 IR-4 – Incident Handling",
        "NIST SP 800-53 Rev 5 IR-6 – Incident Reporting",
        "NIST CSF v2.0 – RS.MI-1 (Incidents are Contained)",
        "CIS Controls v8 – 17.3 Establish and Maintain an Enterprise Process for Reporting Incidents",
    ],
    Severity.HIGH: [
        "NIST SP 800-53 Rev 5 IR-4 – Incident Handling",
        "NIST CSF v2.0 – DE.AE-2 (Detected Events are Analyzed)",
    ],
}

# ── Deduplication helper ──────────────────────────────────────────────────────
def _unique_refs(existing: list[str], additions: list[str]) -> list[str]:
    seen = set(existing)
    result = list(existing)
    for ref in additions:
        if ref not in seen:
            seen.add(ref)
            result.append(ref)
    return result


# ── Public API ────────────────────────────────────────────────────────────────
def enrich(finding: Finding) -> Finding:
    """Return the finding with NIST and CIS references appended."""
    additions = list(_CATEGORY_REFS.get(finding.category, []))
    additions += _SEVERITY_EXTRA.get(finding.severity, [])
    finding.references = _unique_refs(finding.references, additions)
    return finding

"""CIS Controls v8 reference definitions and compliance matrix builder.

Controls selected from CIS Controls v8 (2021) that are applicable to
network firewall security auditing. Each entry: control_id -> (title, ig_level)
where ig_level is the Implementation Group (1=basic, 2=foundational, 3=advanced).
"""
import re
from dataclasses import dataclass, field

# ── CIS Controls v8 applicable to firewall audit ──────────────────────────────
CONTROLS: dict[str, dict] = {
    "4.1":  {"title": "Establish and Maintain a Secure Configuration Process",
             "ig": 1, "group": "Secure Configuration"},
    "4.2":  {"title": "Establish and Maintain a Secure Configuration Process for Network Infrastructure",
             "ig": 1, "group": "Secure Configuration"},
    "4.4":  {"title": "Implement and Manage a Firewall on Servers",
             "ig": 1, "group": "Secure Configuration"},
    "4.5":  {"title": "Implement and Manage a Firewall on End-User Devices",
             "ig": 1, "group": "Secure Configuration"},
    "4.6":  {"title": "Securely Manage Enterprise Assets and Software",
             "ig": 2, "group": "Secure Configuration"},
    "5.2":  {"title": "Use Unique Passwords",
             "ig": 1, "group": "Account Management"},
    "5.3":  {"title": "Disable Dormant Accounts",
             "ig": 1, "group": "Account Management"},
    "5.4":  {"title": "Restrict Administrator Privileges to Dedicated Administrator Accounts",
             "ig": 1, "group": "Account Management"},
    "6.3":  {"title": "Require MFA for Externally-Exposed Applications",
             "ig": 1, "group": "Access Control Management"},
    "6.4":  {"title": "Require MFA for Remote Network Access",
             "ig": 2, "group": "Access Control Management"},
    "6.5":  {"title": "Require MFA for Administrative Access",
             "ig": 2, "group": "Access Control Management"},
    "7.3":  {"title": "Perform Automated Operating System Patch Management",
             "ig": 1, "group": "Vulnerability Management"},
    "7.4":  {"title": "Perform Automated Application Patch Management",
             "ig": 2, "group": "Vulnerability Management"},
    "8.1":  {"title": "Establish and Maintain an Audit Log Management Process",
             "ig": 1, "group": "Audit Log Management"},
    "8.2":  {"title": "Collect Audit Logs",
             "ig": 1, "group": "Audit Log Management"},
    "8.4":  {"title": "Standardize Time Synchronization",
             "ig": 2, "group": "Audit Log Management"},
    "8.5":  {"title": "Collect Detailed Audit Logs",
             "ig": 2, "group": "Audit Log Management"},
    "8.9":  {"title": "Centralize Audit Logs",
             "ig": 2, "group": "Audit Log Management"},
    "8.11": {"title": "Conduct Audit Log Reviews",
             "ig": 2, "group": "Audit Log Management"},
    "9.3":  {"title": "Maintain and Enforce Network-Based URL Filters",
             "ig": 2, "group": "Email and Web Browser Protections"},
    "9.6":  {"title": "Block Unnecessary File Types",
             "ig": 2, "group": "Email and Web Browser Protections"},
    "10.1": {"title": "Deploy and Maintain Anti-Malware Software",
             "ig": 1, "group": "Malware Defenses"},
    "11.2": {"title": "Perform Automated Backups",
             "ig": 1, "group": "Data Recovery"},
    "11.3": {"title": "Protect Recovery Data",
             "ig": 1, "group": "Data Recovery"},
    "12.1": {"title": "Ensure Network Infrastructure is Up-to-Date",
             "ig": 1, "group": "Network Infrastructure Management"},
    "12.2": {"title": "Establish and Maintain a Secure Network Architecture",
             "ig": 2, "group": "Network Infrastructure Management"},
    "12.3": {"title": "Securely Manage Network Infrastructure",
             "ig": 2, "group": "Network Infrastructure Management"},
    "12.6": {"title": "Use of Secure Network Management and Communication Protocols",
             "ig": 2, "group": "Network Infrastructure Management"},
    "13.1": {"title": "Centralize Security Event Alerting",
             "ig": 2, "group": "Network Monitoring and Defense"},
    "13.3": {"title": "Deploy a Network Intrusion Detection Solution",
             "ig": 2, "group": "Network Monitoring and Defense"},
    "13.4": {"title": "Perform Traffic Filtering Between Network Segments",
             "ig": 1, "group": "Network Monitoring and Defense"},
    "13.6": {"title": "Collect Network Traffic Flow Logs",
             "ig": 2, "group": "Network Monitoring and Defense"},
    "13.8": {"title": "Deploy a Network Intrusion Prevention Solution",
             "ig": 2, "group": "Network Monitoring and Defense"},
}

# Regex to extract CIS Control IDs from reference strings.
# Handles formats:
#   "CIS Control 8.4 – …"
#   "CIS Controls v8 – 13.4 …"
#   "CIS Sophos Benchmark §3.1"  (ignored — not in CIS Controls v8)
_CIS_RE = re.compile(
    r'CIS\s+(?:Controls?\s+(?:v\d+\s*[-–]\s*)?|Benchmark\s*§)(\d+\.\d+)',
    re.IGNORECASE,
)


def extract_ids(references: list[str]) -> list[str]:
    """Pull CIS Control IDs from a finding's references list."""
    ids: list[str] = []
    for ref in references:
        for m in _CIS_RE.finditer(ref):
            cid = m.group(1)
            if cid in CONTROLS and cid not in ids:
                ids.append(cid)
    return ids


@dataclass
class ControlStatus:
    control_id: str
    title: str
    ig: int
    group: str
    status: str        # "fail" | "pass" | "not_tested"
    severity: str = ""  # worst severity of failing findings
    finding_titles: list[str] = field(default_factory=list)


def build_matrix(findings) -> list[ControlStatus]:
    """Build a CIS Controls v8 compliance matrix from the findings list.

    Status logic:
      fail       — at least one non-Info finding references this control
      pass       — at least one finding references this control but all are Info
      not_tested — control is in scope but no finding references it
    """
    from .models import Severity
    _SEV_ORDER = {s.value: i for i, s in enumerate(Severity)}

    # Accumulate references: control_id -> list of (severity, title)
    hits: dict[str, list[tuple[str, str]]] = {}
    for f in findings:
        for cid in extract_ids(f.references):
            hits.setdefault(cid, []).append((f.severity.value, f.title))

    result: list[ControlStatus] = []
    for cid, meta in sorted(CONTROLS.items(), key=lambda x: tuple(int(p) for p in x[0].split("."))):
        if cid not in hits:
            status = ControlStatus(
                control_id=cid,
                title=meta["title"],
                ig=meta["ig"],
                group=meta["group"],
                status="not_tested",
            )
        else:
            failing = [(s, t) for s, t in hits[cid] if s != "Info"]
            if failing:
                worst = min(failing, key=lambda x: _SEV_ORDER[x[0]])
                status = ControlStatus(
                    control_id=cid,
                    title=meta["title"],
                    ig=meta["ig"],
                    group=meta["group"],
                    status="fail",
                    severity=worst[0],
                    finding_titles=[t for _, t in failing],
                )
            else:
                status = ControlStatus(
                    control_id=cid,
                    title=meta["title"],
                    ig=meta["ig"],
                    group=meta["group"],
                    status="pass",
                    finding_titles=[t for _, t in hits[cid]],
                )
        result.append(status)
    return result

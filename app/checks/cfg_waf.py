"""Config checks — WAF / Web Server Protection (CIS Sophos Benchmark §5.5)."""
from .models import Finding, Severity
from .utils import v as _v, off as _off

_S = "Config — WAF / Web Server Protection"

# Zone names that indicate an internet-facing source
_WAN_ZONES = {"wan", "internet", "untrust", "external", "outside", "public"}
# Zone names that indicate backend server zones
_SERVER_ZONES = {"dmz", "dmz1", "servers", "web", "backend", "internal", "lan", "server"}


def run(cfg) -> list[Finding]:
    findings: list[Finding] = []

    # ── Detect inbound rules from WAN to internal/server zones ───────────────
    wan_inbound = [
        r for r in cfg.firewall_rules
        if r.get("action", "").lower() in ("accept", "allow")
        and not r.get("status", "enable").lower() in ("disable", "disabled")
        and any(z.strip().lower() in _WAN_ZONES or any(w in z.lower() for w in ("wan", "untrust"))
                for z in r.get("src_zones", []))
        and any(z.strip().lower() in _SERVER_ZONES or any(w in z.lower() for w in ("dmz", "server"))
                for z in r.get("dst_zones", []))
    ]

    # ── CIS 5.5 – WAF not configured when inbound rules exist ────────────────
    if not cfg.waf_policies:
        if wan_inbound:
            affected_names = [r.get("name", f"Rule #{r.get('policy_index','?')}") for r in wan_inbound]
            findings.append(Finding(
                severity=Severity.HIGH,
                category=_S,
                title="CIS 5.5 – No WAF protection policies configured for WAN→server rules",
                detail=(
                    "Firewall rules allow WAN traffic directly to internal/DMZ servers "
                    "but no Web Application Firewall protection policies are configured. "
                    "Without WAF, web application attacks (SQLi, XSS, CSRF, path traversal) "
                    "reach servers uninspected."
                ),
                recommendation=(
                    "Navigate to Protect → Web server → Protection policies → Add policy. "
                    "Enable cookie signing, URL hardening, form hardening, and AV scanning. "
                    "Attach the WAF policy to each inbound firewall rule: "
                    "Edit rule → Web server protection → select policy → Save. "
                    "Aligns with CIS Sophos Benchmark §5.5."
                ),
                references=[
                    "CIS Sophos Benchmark §5.5",
                    "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                    "OWASP A03:2021 – Injection",
                    "OWASP A07:2021 – Identification and Authentication Failures",
                    "CIS Control 13.10 – Perform Application Layer Filtering",
                ],
                location=(
                    "Protect → Web server → Protection policies → Add → configure → Apply\n"
                    "Firewall → Rules and policies → Edit each inbound rule → "
                    "Web server protection → select policy → Save"
                ),
                affected=affected_names[:20],
                exploitability="High", impact_scope="Network", exposure="External",
            ))
        else:
            # No inbound rules AND no WAF — informational only
            findings.append(Finding(
                severity=Severity.INFO,
                category=_S,
                title="CIS 5.5 – WAF not configured (no WAN-to-server rules detected)",
                detail=(
                    "No WAF protection policies or WAN-to-server inbound rules were found. "
                    "If this device protects web-facing servers, configure WAF protection policies. "
                    "This may be expected if the firewall does not terminate reverse-proxy traffic."
                ),
                recommendation=(
                    "If web servers are published through this firewall, configure WAF policies "
                    "under Protect → Web server. Aligns with CIS Sophos Benchmark §5.5."
                ),
                references=["CIS Sophos Benchmark §5.5"],
                location="Protect → Web server → Protection policies → Add",
                exploitability="Low", impact_scope="Local", exposure="Internal",
            ))
        return findings

    # ── Per-policy checks ─────────────────────────────────────────────────────
    for policy in cfg.waf_policies:
        name = _v(policy, "Name", "PolicyName", "RuleName") or "(unnamed)"

        # ── Cookie signing ────────────────────────────────────────────────────
        cookie_sign = _v(policy, "CookieSigning", "SignCookie", "CookieProtection",
                         "SignCookies", "CookieSecurity")
        if _off(cookie_sign):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=_S,
                title=f"CIS 5.5 – WAF policy '{name}': cookie signing not enabled",
                detail=(
                    f"WAF protection policy '{name}' does not have cookie signing enabled. "
                    "Cookie signing is a defence-in-depth control: it cryptographically binds "
                    "cookies to the server so that tampered or forged cookies are rejected at "
                    "the WAF layer. An attacker exploiting this gap still needs an existing "
                    "session management weakness in the protected application."
                ),
                recommendation=(
                    f"Edit WAF policy '{name}' → Protection → enable 'Cookie signing'. "
                    "This reduces session-related risk even when the application itself sets "
                    "weak cookies. Aligns with CIS Sophos Benchmark §5.5."
                ),
                references=[
                    "CIS Sophos Benchmark §5.5",
                    "MITRE ATT&CK T1539 – Steal Web Session Cookie",
                    "OWASP A07:2021 – Identification and Authentication Failures",
                    "CWE-384 – Session Fixation",
                ],
                location=(
                    f"Protect → Web server → Protection policies → Edit '{name}'\n"
                    "→ Protection → Cookie signing → Enable → Save"
                ),
                exploitability="Medium", impact_scope="Network", exposure="External",
            ))

        # ── Static URL hardening ──────────────────────────────────────────────
        url_hard = _v(policy, "URLHardening", "StaticURLHardening", "URLProtection",
                      "HardenURL", "StaticURL")
        if _off(url_hard):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=_S,
                title=f"CIS 5.5 – WAF policy '{name}': static URL hardening not enabled",
                detail=(
                    f"WAF policy '{name}' does not have static URL hardening enabled. "
                    "Static URL hardening prevents attackers from requesting arbitrary URLs "
                    "not seen in legitimate application responses — blocking path traversal, "
                    "forced browsing, and direct object reference attacks."
                ),
                recommendation=(
                    f"Edit WAF policy '{name}' → Protection → enable 'Static URL hardening'. "
                    "Sophos WAF will sign URLs in server responses and reject unsigned URL requests. "
                    "Aligns with CIS Sophos Benchmark §5.5."
                ),
                references=[
                    "CIS Sophos Benchmark §5.5",
                    "MITRE ATT&CK T1083 – File and Directory Discovery",
                    "OWASP A01:2021 – Broken Access Control",
                    "CWE-22 – Path Traversal",
                ],
                location=(
                    f"Protect → Web server → Protection policies → Edit '{name}'\n"
                    "→ Protection → Static URL hardening → Enable → Save"
                ),
                exploitability="Medium", impact_scope="Network", exposure="External",
            ))

        # ── Form hardening ────────────────────────────────────────────────────
        form_hard = _v(policy, "FormHardening", "HTMLFormHardening", "FormProtection",
                       "HardenForms")
        if _off(form_hard):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=_S,
                title=f"CIS 5.5 – WAF policy '{name}': form hardening not enabled",
                detail=(
                    f"WAF policy '{name}' does not have form hardening enabled. "
                    "Form hardening prevents manipulation of hidden form fields and forces "
                    "field values to remain within server-defined bounds — blocking parameter "
                    "tampering, mass assignment, and hidden field manipulation attacks."
                ),
                recommendation=(
                    f"Edit WAF policy '{name}' → Protection → enable 'Form hardening'. "
                    "Sophos WAF cryptographically signs form elements in server responses "
                    "and rejects tampered submissions. "
                    "Aligns with CIS Sophos Benchmark §5.5."
                ),
                references=[
                    "CIS Sophos Benchmark §5.5",
                    "OWASP A03:2021 – Injection",
                    "OWASP A04:2021 – Insecure Design",
                    "CWE-472 – External Control of Assumed-Immutable Web Parameter",
                ],
                location=(
                    f"Protect → Web server → Protection policies → Edit '{name}'\n"
                    "→ Protection → Form hardening → Enable → Save"
                ),
                exploitability="Medium", impact_scope="Network", exposure="External",
            ))

        # ── AV scanning in WAF ────────────────────────────────────────────────
        waf_av = _v(policy, "AntiVirus", "AVScanning", "MalwareScan", "AV",
                    "VirusScanning", "AVProtection")
        if _off(waf_av):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=_S,
                title=f"CIS 5.5 – WAF policy '{name}': antivirus scanning not enabled",
                detail=(
                    f"WAF policy '{name}' does not scan HTTP request/response bodies for malware. "
                    "Without AV scanning at the WAF layer, malware uploaded via web forms "
                    "or embedded in server responses reaches end-users unscanned."
                ),
                recommendation=(
                    f"Edit WAF policy '{name}' → Protection → enable 'Antivirus'. "
                    "WAF-layer AV scanning applies even when HTTPS inspection is not deployed, "
                    "since the WAF terminates the connection. "
                    "Aligns with CIS Sophos Benchmark §5.5."
                ),
                references=[
                    "CIS Sophos Benchmark §5.5",
                    "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                    "CIS Control 10.1 – Deploy and Maintain Anti-Malware Software",
                ],
                location=(
                    f"Protect → Web server → Protection policies → Edit '{name}'\n"
                    "→ Protection → Antivirus → Enable → Save"
                ),
                exploitability="Medium", impact_scope="Network", exposure="External",
            ))

        # ── Bot/client reputation ─────────────────────────────────────────────
        bot_rep = _v(policy, "BotReputation", "ClientReputation", "BotProtection",
                     "ReputationCheck", "BotFilter")
        if _off(bot_rep):
            findings.append(Finding(
                severity=Severity.LOW,
                category=_S,
                title=f"CIS 5.5 – WAF policy '{name}': bot/client reputation checking not enabled",
                detail=(
                    f"WAF policy '{name}' does not enforce client reputation checking. "
                    "Without reputation filtering, known scanner IPs, botnets, and malicious "
                    "automated clients can probe the protected web application freely."
                ),
                recommendation=(
                    f"Edit WAF policy '{name}' → Protection → enable reputation-based filtering "
                    "or 'Block clients with bad reputation'. "
                    "Aligns with CIS Sophos Benchmark §5.5."
                ),
                references=[
                    "CIS Sophos Benchmark §5.5",
                    "MITRE ATT&CK T1595 – Active Scanning",
                    "OWASP A05:2021 – Security Misconfiguration",
                ],
                location=(
                    f"Protect → Web server → Protection policies → Edit '{name}'\n"
                    "→ Protection → Reputation → Enable → Save"
                ),
                exploitability="Medium", impact_scope="Network", exposure="External",
            ))

    # ── Rules with no WAF policy attached ────────────────────────────────────
    if wan_inbound:
        rules_no_waf = [
            r.get("name", f"Rule #{r.get('policy_index','?')}")
            for r in wan_inbound
            if not r.get("waf_policy", "").strip()
        ]
        if rules_no_waf:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=_S,
                title="CIS 5.5 – WAN-to-server rules not using WAF protection",
                detail=(
                    "WAF protection policies exist but these inbound rules do not have one "
                    "attached. Web application traffic reaches the backend servers without "
                    "WAF inspection — all application-layer attacks bypass detection."
                ),
                recommendation=(
                    "Edit each affected rule → Web server protection → assign a WAF policy → Save. "
                    "Aligns with CIS Sophos Benchmark §5.5."
                ),
                references=[
                    "CIS Sophos Benchmark §5.5",
                    "MITRE ATT&CK T1190 – Exploit Public-Facing Application",
                    "OWASP A03:2021 – Injection",
                ],
                location=(
                    "Firewall → Rules and policies → Firewall rules\n"
                    "→ Edit inbound rule → Web server protection → select WAF policy → Save"
                ),
                affected=rules_no_waf[:20],
                exploitability="High", impact_scope="Network", exposure="External",
            ))

    return findings

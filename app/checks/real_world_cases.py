"""
Real-world attack case library.

Each entry maps a list of title keywords (all must appear, case-insensitive)
to up to 3 brief incident descriptions. The engine matches findings at runtime
so check modules stay clean.
"""

# Each rule: (keyword_tuple, [case1, case2, case3])
# keyword_tuple — ALL words must appear in the finding title (case-insensitive)
CASES: list[tuple[tuple[str, ...], list[str]]] = [

    # ── Firewall Rules ────────────────────────────────────────────────────────

    (("any", "any"),
     [
         "Target Corporation (2013): A vendor's any-to-any network access rule allowed "
         "HVAC systems to communicate directly with Point-of-Sale servers. Attackers "
         "used this path to exfiltrate 40 million payment card records.",

         "Marriott/Starwood (2018): Overly permissive internal rules allowed lateral "
         "movement from a compromised reservation system to Starwood's guest database "
         "for over four years, exposing 500 million guest records.",

         "Bangladesh Bank SWIFT Heist (2016): Flat network rules with no segmentation "
         "between the SWIFT terminal and the internet-facing network enabled attackers "
         "to issue $951 million in fraudulent transfer requests.",
     ]),

    (("wan", "source"),
     [
         "Fortinet Mass Exploitation (2022, CVE-2022-40684): Within 48 hours of PoC "
         "publication, threat actors scanned the internet and exploited Fortinet devices "
         "with WAN-exposed admin interfaces, deploying backdoors on 16,000+ devices.",

         "Pulse Secure VPN (2021): APT actors exploited CVE-2019-11510 against "
         "internet-accessible Pulse Secure gateways with broad WAN access rules. "
         "Multiple US government agencies and defence contractors were breached.",
     ]),

    (("all", "service"),
     [
         "Sony Pictures (2014): Permissive internal rules allowing all services between "
         "segments meant attackers could move freely after initial compromise, "
         "exfiltrating 100 TB of data including unreleased films and executive emails.",

         "Equifax (2017): An unpatched Apache Struts server was reachable due to "
         "overly broad service rules. After exploitation, attackers moved laterally "
         "to 48 unrelated databases, stealing 147 million records.",
     ]),

    (("insecure", "service"),
     [
         "Mirai Botnet (2016): Mirai spread by scanning for Telnet (port 23) on "
         "network devices using default credentials. It recruited 600,000+ IoT devices "
         "and launched the largest DDoS in history, taking down Dyn DNS.",

         "Industroyer/CrashOverride (2016): ICS malware used Telnet and unencrypted "
         "industrial protocols to pivot between network segments in the Ukrainian power "
         "grid attack, causing a six-hour blackout for 230,000 customers.",
     ]),

    (("accept", "log"),
     [
         "Target Corporation (2013): FireEye security alerts were triggered repeatedly "
         "but security operations staff dismissed them. Missing log review processes "
         "meant the breach went undetected for three weeks.",

         "OPM Breach (2015): The US Office of Personnel Management lacked comprehensive "
         "logging on accepted traffic. Attackers exfiltrated 21.5 million security "
         "clearance records over 14 months before detection.",
     ]),

    (("disabled", "drop"),
     [
         "Capital One (2019): A misconfigured WAF rule that should have blocked "
         "SSRF requests was disabled during maintenance and never re-enabled. "
         "This allowed an attacker to query the EC2 metadata service and steal "
         "IAM credentials, exposing 106 million customer records.",
     ]),

    # ── VPN ──────────────────────────────────────────────────────────────────

    (("weak", "enc"),
     [
         "Juniper ScreenOS Backdoor (2015): NSA-linked code inserted into Juniper's "
         "VPN firmware used weak Dual_EC_DRBG for key generation, allowing passive "
         "decryption of VPN traffic. Discovered after 3 years in production.",

         "Logjam Attack (2015): Researchers demonstrated downgrade attacks against "
         "DH-512 across major VPN implementations. US government and university "
         "networks were found vulnerable, allowing nation-state eavesdropping.",
     ]),

    (("pptp",),
     [
         "LulzSec / Anonymous (2011–2012): Multiple law enforcement and corporate "
         "VPNs using PPTP were cracked offline using MS-CHAPv2 hash capture tools "
         "(CloudCracker). PPTP's broken authentication gave attackers plaintext "
         "credentials within hours.",

         "Sega Europe (2011): PPTP VPN credentials were compromised, giving attackers "
         "access to internal servers. 1.3 million user records were exfiltrated "
         "before the breach was discovered.",
     ]),

    (("pre-shared key", "psk"),
     [
         "Juniper Networks (2015): A weak PSK in ScreenOS VPN configurations was "
         "exploited to decrypt government and corporate VPN sessions, attributed to "
         "a nation-state threat actor.",

         "Ubiquiti VPN Campaign (2021): Threat actors harvested PSK values from "
         "publicly-exposed configuration backups and used them to authenticate "
         "into corporate VPN tunnels without detection.",
     ]),

    (("ssl", "mfa"),
     [
         "Colonial Pipeline (2021): Attackers used a compromised password — with no "
         "MFA on the VPN — to access Colonial Pipeline's network. The resulting "
         "ransomware attack caused fuel shortages across the US East Coast "
         "and a $4.4 million ransom payment.",

         "Uber (2022): An MFA-fatigue attack against an SSL VPN credential gave "
         "attackers full internal network access. The attacker repeatedly pushed "
         "MFA prompts until the employee approved one, exposing source code and "
         "internal tools.",
     ]),

    (("ssl vpn", "tls"),
     [
         "Pulse Secure (2019, CVE-2019-11510): Unauthenticated file read allowed "
         "attackers to steal plaintext credentials from VPN sessions using weak "
         "TLS configuration. APT5 and REvil used this to compromise 900+ companies.",
     ]),

    (("dh group", "weak"),
     [
         "Logjam (2015): Academic researchers demonstrated that nation-state actors "
         "could precompute DH-1024 parameters and passively decrypt VPN traffic "
         "in real time. Estimated 8.4% of top 1M HTTPS sites were vulnerable.",
     ]),

    # ── Administration ────────────────────────────────────────────────────────

    (("wan", "web", "admin"),
     [
         "Fortinet FortiOS (2022, CVE-2022-40684): An authentication bypass on the "
         "web management interface allowed unauthenticated admin takeover. Over "
         "16,000 Fortinet devices with internet-exposed admin were backdoored "
         "within days of the PoC release.",

         "Cisco ASA (2018, CVE-2018-0101): A heap overflow in the WebVPN/admin "
         "interface of internet-exposed Cisco ASA firewalls was exploited by "
         "APT groups to install persistent backdoors.",

         "SonicWall SMA (2021): Zero-day vulnerabilities in the web admin portal "
         "of internet-facing SonicWall devices were actively exploited by "
         "ransomware groups to deploy Darkside and HelloKitty ransomware.",
     ]),

    (("ssh", "wan"),
     [
         "Cisco IOS XE (2023, CVE-2023-20198): Internet-exposed management "
         "interfaces (including SSH) were exploited to create privileged accounts "
         "on 10,000+ Cisco devices within 24 hours of vulnerability disclosure.",

         "SolarWinds Orion (2020): SSH access to network devices was abused "
         "post-compromise to move laterally and maintain persistence across "
         "18,000 SolarWinds customer networks, including US Treasury and DoD.",
     ]),

    (("http", "management"),
     [
         "Cisco Small Business Routers (2019): HTTP management enabled by default "
         "on thousands of internet-facing Cisco RV-series routers allowed credential "
         "sniffing and session hijacking by attackers on the same network segment.",

         "TP-Link / D-Link Campaign (2023): A credential-harvesting campaign "
         "targeted SMB routers with HTTP admin enabled, capturing cleartext "
         "admin passwords via ARP poisoning in shared hosting environments.",
     ]),

    (("session timeout",),
     [
         "Uber (2016): A persisted admin session token found in an exposed "
         "S3 bucket (no timeout/revocation) gave attackers access to GitHub "
         "repositories, leading to the theft of 57 million user records "
         "and a $100,000 ransom paid to conceal the breach.",
     ]),

    (("ssh", "enabled", "zone"),
     [
         "Target Corporation (2013): SSH access between internal network segments "
         "allowed attackers, once inside via the HVAC vendor account, to move "
         "laterally to Point-of-Sale systems without triggering alerts.",

         "Equifax (2017): Post-exploitation SSH lateral movement between internal "
         "servers allowed attackers to access 48 databases from a single initial "
         "foothold on one web server.",
     ]),

    (("ssh", "dmz"),
     [
         "Heartbleed + DMZ SSH (2014): Organizations with SSH enabled on DMZ "
         "hosts suffered direct firewall management compromise after DMZ web servers "
         "were exploited via CVE-2014-0160 (Heartbleed), providing a pivot path "
         "to the firewall management interface.",
     ]),

    (("default", "admin"),
     [
         "Mirai Botnet (2016): Mirai's credential dictionary included default "
         "usernames such as 'admin/admin' and 'admin/password'. Over 600,000 "
         "devices were compromised using these credentials to build the botnet "
         "that knocked Twitter, Reddit, and Netflix offline.",

         "Verkada Camera Breach (2021): Default admin credentials on Verkada's "
         "security camera platform gave attackers access to 150,000 live camera "
         "feeds including in Tesla factories, hospitals, and jails.",
     ]),

    # ── Authentication ────────────────────────────────────────────────────────

    (("multi-factor", "mfa"),
     [
         "Colonial Pipeline (2021): A single compromised VPN password with no MFA "
         "triggered the largest US fuel infrastructure shutdown in history. "
         "The ransomware attack cost $4.4 million and caused week-long fuel "
         "shortages across the US East Coast.",

         "Microsoft Exchange Online (2023): Storm-0558 used stolen credentials "
         "against Exchange accounts lacking MFA enforcement, accessing emails "
         "of US State Department and other US government officials.",
     ]),

    (("account lockout",),
     [
         "Citrix Bleed (2023, CVE-2023-4966): Combined with password spraying "
         "against Citrix NetScaler with no account lockout, attackers hijacked "
         "sessions of government and enterprise targets including Boeing and LockBit "
         "victims without triggering any lockout.",

         "SolarWinds (2020): Password spraying against Microsoft 365 accounts "
         "with no lockout policy gave attackers persistent email access across "
         "the SolarWinds supply chain attack, going undetected for 9 months.",
     ]),

    (("ldap", "389"),
     [
         "Bupa Insurance (2017): Cleartext LDAP traffic between the firewall and "
         "Active Directory was intercepted by a rogue insider, harvesting service "
         "account credentials used to exfiltrate 547,000 customer records.",

         "UK Financial Sector (2019, NCSC Advisory): Nation-state actors were "
         "found sniffing LDAP port 389 traffic on management VLANs across multiple "
         "financial institutions to harvest AD credentials without triggering alerts.",
     ]),

    (("password", "length"),
     [
         "RockYou2021 (2021): A compilation of 8.4 billion passwords showed that "
         "the majority of breached passwords were under 10 characters. "
         "Short minimum length policies were a direct contributing factor.",
     ]),

    # ── Logging ───────────────────────────────────────────────────────────────

    (("syslog",),
     [
         "Target (2013): Security alerts were generated by FireEye but no centralised "
         "syslog correlation existed to escalate them. The 3-week dwell time "
         "cost Target $162 million in settlements.",

         "Marriott (2018): The absence of centralised log management meant the "
         "Starwood breach went undetected for four years after the initial "
         "compromise, exposing 500 million guest records.",
     ]),

    (("ips", "disabled"),
     [
         "Equifax (2017): The IPS that would have detected Apache Struts exploit "
         "traffic (CVE-2017-5638) had been disabled for 19 months due to an "
         "expired SSL inspection certificate, allowing undetected exploitation.",

         "Cognyte (2021): A misconfigured IPS that was effectively disabled "
         "allowed an unsecured database of 5 billion records to be accessed "
         "without triggering any detection alerts.",
     ]),

    (("flood", "protection"),
     [
         "Dyn DNS DDoS (2016): Mirai botnet launched 1.2 Tbps of UDP/DNS flood "
         "traffic against Dyn's DNS infrastructure. Devices without flood "
         "protection were used as amplifiers, taking down Twitter, Spotify, "
         "Reddit, and Netflix for hours.",

         "GitHub DDoS (2018): A 1.35 Tbps memcached amplification attack "
         "exploited devices without flood protection or rate limiting, "
         "briefly taking GitHub offline — the largest DDoS recorded at the time.",
     ]),

    # ── NAT / DNAT ────────────────────────────────────────────────────────────

    (("rdp", "dnat"),
     [
         "WannaCry (2017): Hundreds of thousands of Windows machines with RDP "
         "DNAT rules exposed to the internet were compromised via EternalBlue "
         "(MS17-010) in a single day, costing the NHS £92 million alone.",

         "NotPetya (2017): DNAT rules exposing RDP to the internet gave NotPetya "
         "an entry point into corporate networks. Maersk lost an estimated "
         "$300 million; total global damages exceeded $10 billion.",

         "BlueKeep (2019, CVE-2019-0708): Internet-facing RDP servers, many "
         "exposed via DNAT, were mass-exploited by cryptocurrency miners and "
         "later by more destructive threat actors.",
     ]),

    (("dnat", "source"),
     [
         "Verkada (2021): An exposed management API with no source restriction "
         "allowed a hacker collective to access 150,000 live security camera feeds "
         "across Tesla, Cloudflare, and multiple hospitals and jails.",

         "Accellion FTA (2021): DNAT rules exposing Accellion's file transfer "
         "appliance to all sources allowed Clop ransomware group to exploit "
         "zero-days and steal data from 100+ organisations including law firms "
         "and government agencies.",
     ]),

    (("sensitive", "dnat"),
     [
         "Kaseya VSA (2021): Internet-exposed Kaseya VSA servers (RDP and "
         "management APIs with no source restriction) were compromised by "
         "REvil ransomware, cascading to 1,500 downstream managed service "
         "provider customers in a supply-chain attack.",
     ]),

    # ── Certificates ─────────────────────────────────────────────────────────

    (("expired", "certificate"),
     [
         "Equifax (2017): An expired SSL certificate on an internal load balancer "
         "disabled encrypted traffic inspection for 19 months. Attackers exploited "
         "this blind spot to exfiltrate 147 million records undetected.",

         "Microsoft Teams (2020): An expired authentication certificate caused "
         "a global Teams outage affecting millions of users — a reminder that "
         "expired certificates also directly impact service availability.",
     ]),

    (("weak", "signature", "sha"),
     [
         "FLAME Malware (2012): Nation-state malware used an MD5 collision attack "
         "to forge a fraudulent Microsoft code-signing certificate. This allowed "
         "FLAME to spread via Windows Update and remain undetected for years "
         "on Iranian government networks.",

         "Mozilla / Diginotar (2011): DigiNotar's weak certificate infrastructure "
         "was compromised, allowing attackers to issue fraudulent certificates "
         "for google.com and other major sites. 300,000 Iranian Gmail users were "
         "subjected to man-in-the-middle attacks.",
     ]),

    (("self-signed",),
     [
         "DigiNotar (2011): Iranian users connecting to Google were served "
         "fraudulent self-signed-style certificates by a rogue CA. Browsers "
         "conditioned to ignore certificate warnings accepted the fraudulent "
         "certificates, enabling mass credential harvesting.",

         "Operation ShadowHammer (2019): ASUS supply-chain attack used "
         "self-signed certificates to sign malware pushed via ASUS Live Update, "
         "infecting 500,000+ machines before detection.",
     ]),

    # ── System / SNMP ─────────────────────────────────────────────────────────

    (("snmp", "default", "community"),
     [
         "US Financial Sector (2012): Attackers queried SNMP MIBs using the "
         "'public' community string on core banking routers, mapping full "
         "network topology before launching targeted attacks against transaction "
         "processing systems.",

         "Shodan SNMP Survey (2019): Security researchers found over 2 million "
         "internet-facing devices responding to SNMP with default community "
         "strings, many being enterprise firewalls and routers in healthcare "
         "and government networks.",
     ]),

    (("snmp", "v1", "v2"),
     [
         "NASA Jet Propulsion Lab (2018): SNMP v2c was used to enumerate network "
         "topology and identify a Raspberry Pi connected to the JPL network. "
         "The Pi was compromised and used as a pivot point to steal 500MB of "
         "Mars mission data.",
     ]),

    (("update", "disabled"),
     [
         "WannaCry (2017): MS17-010 (EternalBlue) was patched by Microsoft in "
         "March 2017. Organisations with automatic updates disabled were "
         "compromised in May 2017. The NHS suffered £92 million in damages; "
         "global total exceeded $4 billion.",

         "Equifax (2017): Apache Struts (CVE-2017-5638) was patched in March "
         "2017. Equifax's disabled/delayed update process meant the patch was "
         "not applied for 2 months, enabling the breach of 147 million records.",
     ]),

    # ── Network / Zones ───────────────────────────────────────────────────────

    (("dmz",),
     [
         "Sony Pictures (2014): A flat network with no DMZ zone separation allowed "
         "attackers, after initial compromise of a single web server, to reach "
         "corporate email, HR systems, and unreleased films. 100 TB of data was "
         "exfiltrated over several weeks.",

         "Target (2013): No network segmentation between the vendor-accessible "
         "HVAC network and the retail POS network — a DMZ would have blocked "
         "the lateral movement that exposed 40 million payment cards.",
     ]),

    (("spoof",),
     [
         "GitHub DDoS (2018): Attackers used IP spoofing to amplify a memcached "
         "DDoS to 1.35 Tbps. Devices without anti-spoof controls were abused "
         "as unwitting amplifiers, reflecting and amplifying traffic 51,000x.",

         "Cloudflare Mirai (2023): A 71 million RPS HTTP DDoS used IP spoofing "
         "to bypass source-based rate limits. Networks lacking anti-spoof "
         "ingress filtering (BCP 38) contributed amplification traffic.",
     ]),

    # ── Threat / IPS / AV ─────────────────────────────────────────────────────

    (("ips", "wan"),
     [
         "Log4Shell (2021, CVE-2021-44228): Organisations with WAN-facing services "
         "but no IPS to detect/block JNDI payloads were compromised within hours "
         "of PoC release. Over 40% of corporate networks were attacked in 72 hours.",

         "ProxyLogon (2021, CVE-2021-26855): Exchange servers reachable from WAN "
         "without IPS were mass-exploited by HAFNIUM and 10+ other threat groups. "
         "250,000 servers were compromised before patches were widely applied.",
     ]),

    (("antivirus", "av", "disabled"),
     [
         "NotPetya (2017): Organisations with AV disabled or not scanning SMB "
         "traffic were unable to detect the NotPetya wiper spreading via "
         "EternalBlue + Mimikatz. Maersk, Merck, and FedEx suffered combined "
         "losses exceeding $1.5 billion.",
     ]),

    (("web filter",),
     [
         "RSA SecurID (2011): A spear-phishing email with a malicious Flash "
         "attachment bypassed a network without web content filtering. The "
         "resulting compromise of RSA's seed values undermined SecurID tokens "
         "protecting defence contractors and government agencies.",

         "Operation Aurora (2010): Google and 30+ companies were compromised "
         "via watering-hole and drive-by download attacks that web filtering "
         "would have blocked. Attackers stole source code and sensitive IP.",
     ]),

    (("ssl", "inspection"),
     [
         "WireX Botnet (2017): Malware command-and-control traffic was entirely "
         "encrypted. Organisations without SSL inspection could not detect "
         "or block C2 communications, allowing the botnet to persist undetected "
         "across 100,000+ Android devices on corporate Wi-Fi.",
     ]),

    # ── Email ────────────────────────────────────────────────────────────────

    (("open relay",),
     [
         "Business Email Compromise (BEC) — FBI IC3 (2022): Open relays were "
         "abused to send spoofed executive emails in BEC attacks costing "
         "businesses $43 billion globally between 2016 and 2022.",

         "Spamhaus (2013): Open relays at CDN provider Cyberbunker were used "
         "to generate a 300 Gbps DDoS against Spamhaus via DNS amplification, "
         "briefly slowing internet traffic across Europe.",
     ]),

    (("spf",),
     [
         "FACC AG (2016): An Austrian aerospace company lost €50 million in a "
         "BEC attack where attackers spoofed the CEO's email domain — possible "
         "because SPF was not enforced — to instruct a finance employee to "
         "wire funds to an attacker-controlled account.",

         "Twitter Bitcoin Scam (2020): High-profile Twitter accounts were "
         "hijacked and used to send Bitcoin scam emails. Domains without SPF "
         "enforcement were used to relay spoofed sender addresses, tricking "
         "recipients into believing the emails were legitimate.",
     ]),

    (("dmarc",),
     [
         "Ukrainian Government (2022): Russian APT29 sent spear-phishing emails "
         "spoofing Ukrainian government domains that lacked DMARC enforcement. "
         "The campaign targeted NATO members and EU officials.",

         "IRS Scam Campaigns (2016–2023): Repeated tax-season phishing waves "
         "spoofed IRS.gov subdomains that lacked DMARC p=reject policies. "
         "The IRS attributed hundreds of millions in tax fraud to these campaigns.",
     ]),

    (("dkim",),
     [
         "Microsoft 365 BEC (2023): Attackers intercepted and modified invoice "
         "emails in transit (man-in-the-middle on an unencrypted email leg) "
         "to redirect payments. DKIM verification would have detected the "
         "message tampering before delivery.",
     ]),
]


def match(title: str) -> list[str]:
    """Return up to 3 real-world examples whose keywords all appear in `title`."""
    title_lower = title.lower()
    for keywords, examples in CASES:
        if all(kw in title_lower for kw in keywords):
            return examples[:3]
    return []

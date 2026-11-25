"""Findings engine: turn parsed Nmap results into severity-rated,
actionable findings with plain-language explanations and remediation
steps, plus an explainable 0-100 posture score.

Scoring rule (documented in the README and shown on the report page):
every host starts at 100. Each finding deducts points by severity:
Critical -25, High -15, Medium -8, Low -3, Info -0. The host score is
floored at 0. The scan score is the rounded mean of the host scores.
The breakdown (which finding deducted what) is returned alongside the
score, so the number is auditable, not a black box.
"""

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
DEDUCTIONS = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 0}


def severity_from_cvss(score):
    """Map a CVSS score to a severity band."""
    if score is None:
        return "Medium"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


def score_for_findings(findings):
    """Return ``(score, breakdown)`` for a list of findings.

    ``breakdown`` is a list of ``{"title": ..., "severity": ...,
    "deduction": ...}`` in the order the findings were supplied.
    """
    score = 100
    breakdown = []
    for f in findings:
        sev = f.get("severity", "Info")
        deduction = DEDUCTIONS.get(sev, 0)
        score -= deduction
        breakdown.append({
            "title": f.get("title", ""),
            "severity": sev,
            "deduction": deduction,
        })
    return max(0, score), breakdown


# ---------------------------------------------------------------------------
# Port exposure rules: (port, service name) -> finding template.
# Severity reflects how dangerous the exposure typically is for a small
# business that does not need the service reachable from the network.
# ---------------------------------------------------------------------------

PORT_RISK = {
    23: {
        "severity": "Critical",
        "title": "Telnet is open — logins travel in plain text",
        "explanation": (
            "Telnet sends usernames, passwords and everything typed in "
            "plain text. Anyone able to observe the traffic — on the same "
            "network, or on any hop between client and server — can read "
            "credentials and take over the session."
        ),
        "remediation": [
            "Disable the Telnet service entirely.",
            "Use SSH (port 22) for remote administration instead.",
            "If Telnet cannot be removed yet, restrict it to a management "
            "VLAN and allow only specific administrator IPs.",
        ],
        "references": ["https://owasp.org/www-community/attacks/Brute_force_attack"],
    },
    21: {
        "severity": "High",
        "title": "FTP is open — credentials and files travel in plain text",
        "explanation": (
            "Plain FTP sends usernames, passwords and file contents "
            "unencrypted. It is also a common target for brute-force login "
            "attempts and for anonymous-access abuse."
        ),
        "remediation": [
            "Replace plain FTP with SFTP (over SSH) or FTPS.",
            "If FTP must stay, disable anonymous login and enforce strong "
            "passwords, and restrict access by source IP.",
        ],
        "references": ["https://owasp.org/www-community/attacks/Brute_force_attack"],
    },
    445: {
        "severity": "High",
        "title": "SMB file sharing is exposed (port 445)",
        "explanation": (
            "Port 445 is Windows file sharing (SMB). Exposed SMB has been "
            "behind major ransomware outbreaks (WannaCry used SMBv1), and "
            "it lets attackers enumerate shares, users and, with weak "
            "credentials, read or write files."
        ),
        "remediation": [
            "Block port 445 at the network boundary — SMB should never be "
            "reachable from the internet.",
            "Disable SMBv1 on every machine (it has known critical flaws).",
            "Require SMB signing and strong, unique passwords on shares.",
        ],
        "references": ["https://www.cisa.gov/news-events/alerts/2017/05/12/microsoft-releases-security-updates"],
    },
    3389: {
        "severity": "High",
        "title": "Remote Desktop (RDP) is open",
        "explanation": (
            "RDP is the single most brute-forced service on the internet "
            "and a favourite entry point for ransomware. An exposed RDP "
            "port with a weak password gives an attacker a full desktop "
            "session on the machine."
        ),
        "remediation": [
            "Do not expose RDP to the internet. Use a VPN for remote access.",
            "If it must be reachable, require Network Level Authentication, "
            "enforce multi-factor authentication, and allow only specific "
            "source IPs.",
            "Enable account lockout after a small number of failed logins.",
        ],
        "references": ["https://www.cisa.gov/news-events/alerts/2019/05/21/microsoft-releases-security-updates"],
    },
    3306: {
        "severity": "High",
        "title": "MySQL database port is open",
        "explanation": (
            "A database listening on the network can be probed for weak or "
            "default credentials and, if reached, gives direct access to "
            "the business's data."
        ),
        "remediation": [
            "Bind MySQL to localhost (127.0.0.1) unless remote access is "
            "genuinely required.",
            "If remote access is needed, restrict it to the application "
            "server's IP and require TLS.",
            "Use a strong, unique password for every database account and "
            "remove the anonymous and test accounts.",
        ],
        "references": [],
    },
    5432: {
        "severity": "High",
        "title": "PostgreSQL database port is open",
        "explanation": (
            "A database listening on the network can be probed for weak or "
            "default credentials and, if reached, gives direct access to "
            "the business's data."
        ),
        "remediation": [
            "Bind PostgreSQL to localhost unless remote access is genuinely "
            "required.",
            "If remote access is needed, restrict it to the application "
            "server's IP, require TLS, and use strong per-account passwords.",
        ],
        "references": [],
    },
    6379: {
        "severity": "Critical",
        "title": "Redis is open — often with no password at all",
        "explanation": (
            "Redis ships with no authentication by default. An exposed "
            "Redis instance lets anyone read and overwrite cached data and, "
            "in many configurations, write files or run commands on the "
            "server."
        ),
        "remediation": [
            "Bind Redis to localhost and block port 6379 at the firewall.",
            "Set a strong password (requirepass) and disable the CONFIG "
            "command.",
        ],
        "references": [],
    },
    27017: {
        "severity": "High",
        "title": "MongoDB is open",
        "explanation": (
            "MongoDB has historically been found exposed with no "
            "authentication, leading to large-scale data theft and "
            "ransom demands."
        ),
        "remediation": [
            "Bind MongoDB to localhost and block port 27017 at the firewall.",
            "Enable authentication and use a strong password.",
        ],
        "references": [],
    },
    139: {
        "severity": "Medium",
        "title": "NetBIOS session service is open (port 139)",
        "explanation": (
            "NetBIOS leaks information about the machine — computer name, "
            "logged-in users, shares — and is used in enumeration and "
            "relaying attacks."
        ),
        "remediation": [
            "Disable NetBIOS over TCP/IP on machines that do not need it.",
            "Block ports 137–139 at the network boundary.",
        ],
        "references": [],
    },
    22: {
        "severity": "Low",
        "title": "SSH is open",
        "explanation": (
            "SSH is the standard way to administer servers remotely and is "
            "expected to be open on a managed server — but it is also "
            "brute-forced constantly, so it needs hardening."
        ),
        "remediation": [
            "Disable password logins and use SSH keys only.",
            "Disable root login (PermitRootLogin no) and consider changing "
            "the port or restricting by source IP.",
        ],
        "references": [],
    },
    80: {
        "severity": "Info",
        "title": "Web server (HTTP) is open",
        "explanation": (
            "An HTTP web server is normal for a business website. It is "
            "listed here so you can confirm it is the site you expect — "
            "an unexpected web server is a sign something was installed "
            "without your knowledge."
        ),
        "remediation": [
            "Confirm this web server is intentional.",
            "Redirect HTTP to HTTPS and keep the web server software patched.",
        ],
        "references": [],
    },
    443: {
        "severity": "Info",
        "title": "Web server (HTTPS) is open",
        "explanation": (
            "An HTTPS web server is normal for a business website. It is "
            "listed here so you can confirm it is the site you expect."
        ),
        "remediation": [
            "Confirm this web server is intentional.",
            "Keep the web server and its TLS configuration patched and "
            "use a current TLS version.",
        ],
        "references": [],
    },
    53: {
        "severity": "Low",
        "title": "DNS service is open",
        "explanation": (
            "A DNS server answers name lookups. An open resolver can be "
            "abused for DNS amplification attacks against others."
        ),
        "remediation": [
            "If this machine is not meant to be a public DNS server, block "
            "port 53 at the firewall or configure the resolver to answer "
            "only your own network.",
        ],
        "references": [],
    },
    25: {
        "severity": "Low",
        "title": "SMTP mail service is open",
        "explanation": (
            "An SMTP server is normal for a mail server, but an open or "
            "misconfigured one can be used to relay spam."
        ),
        "remediation": [
            "Confirm this mail server is intentional and requires "
            "authentication for relaying.",
            "Keep the mail software patched.",
        ],
        "references": [],
    },
}


def _port_finding(port):
    """Build a finding for an open port, or a generic one if unknown."""
    rule = PORT_RISK.get(port["port"])
    service = port["service"]
    name = service.get("name") or "unknown"
    product = service.get("product") or ""
    version = service.get("version") or ""
    where = "port %d (%s)" % (port["port"], name)
    if rule:
        return {
            "severity": rule["severity"],
            "title": rule["title"],
            "explanation": rule["explanation"],
            "remediation": list(rule["remediation"]),
            "references": list(rule["references"]),
            "port": port["port"],
            "service": name,
            "product": (product + " " + version).strip(),
            "cve": None,
        }
    return {
        "severity": "Low",
        "title": "Unexpected open port: %s" % where,
        "explanation": (
            "This port is open but is not a service this scanner recognises "
            "as standard for a small business. Unexpected open ports are "
            "worth checking — they can be forgotten software, a misconfigured "
            "service, or something installed without approval."
        ),
        "remediation": [
            "Identify what is listening on this port and why.",
            "If it is not needed, stop the service and close the port.",
        ],
        "references": [],
        "port": port["port"],
        "service": name,
        "product": (product + " " + version).strip(),
        "cve": None,
    }


def _script_findings(port, host_address):
    """Build findings from NSE script output attached to a port."""
    findings = []
    for script in port.get("scripts", []):
        sid = script.get("id", "")
        output = script.get("output", "")
        if sid == "vulners":
            from .parser import parse_vulners_output
            for entry in parse_vulners_output(output):
                sev = severity_from_cvss(entry["score"])
                score_txt = ("CVSS %.1f" % entry["score"]) if entry["score"] is not None else "no CVSS score published"
                findings.append({
                    "severity": sev,
                    "title": "%s reported on %s (%s)" % (
                        entry["cve"], port["service"].get("name") or "port %d" % port["port"], score_txt),
                    "explanation": (
                        "The vulnerability scanner matched the software on "
                        "this port against a public vulnerability database "
                        "and found %s. %s means the flaw is publicly known "
                        "and, depending on the severity, may already have "
                        "public exploit code." % (entry["cve"], score_txt)
                    ),
                    "remediation": [
                        "Update the affected software to a version that fixes %s." % entry["cve"],
                        "If no update is available yet, look up the CVE for a "
                        "workaround (for example, disabling the vulnerable feature).",
                        "Re-scan after patching to confirm the finding is gone.",
                    ],
                    "references": [entry["url"]],
                    "port": port["port"],
                    "service": port["service"].get("name") or "",
                    "product": "",
                    "cve": entry["cve"],
                })
        elif sid == "ssl-heartbleed" and "VULNERABLE" in output:
            findings.append({
                "severity": "Critical",
                "title": "Heartbleed (CVE-2014-0160) — the server leaks memory over TLS",
                "explanation": (
                    "The TLS heartbeat extension on this service is "
                    "vulnerable to Heartbleed: an attacker can read up to "
                    "64 KB of the server's memory per request, which can "
                    "expose private keys, session tokens and passwords."
                ),
                "remediation": [
                    "Update OpenSSL to a fixed version immediately.",
                    "Revoke and re-issue TLS certificates and rotate secrets "
                    "after patching.",
                ],
                "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160"],
                "port": port["port"],
                "service": port["service"].get("name") or "",
                "product": "",
                "cve": "CVE-2014-0160",
            })
        elif sid == "ssl-poodle" and "VULNERABLE" in output:
            findings.append({
                "severity": "Medium",
                "title": "POODLE (CVE-2014-3566) — SSLv3 is still enabled",
                "explanation": (
                    "The service still accepts SSLv3, which is broken by "
                    "design (POODLE). An attacker who can intercept traffic "
                    "can decrypt parts of encrypted sessions."
                ),
                "remediation": [
                    "Disable SSLv3 and all SSL/TLS versions below TLS 1.2.",
                    "Keep the server software patched.",
                ],
                "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566"],
                "port": port["port"],
                "service": port["service"].get("name") or "",
                "product": "",
                "cve": "CVE-2014-3566",
            })
    return findings


def analyse_host(host):
    """Analyse one parsed host dict and return its findings list."""
    findings = []
    if host.get("status") != "up":
        return findings
    for port in host.get("ports", []):
        if port.get("state") != "open":
            continue
        findings.append(_port_finding(port))
        findings.extend(_script_findings(port, host.get("address")))
    for script in host.get("host_scripts", []):
        if script.get("id") == "smb-vuln-ms17-010" and "VULNERABLE" in script.get("output", ""):
            findings.append({
                "severity": "Critical",
                "title": "EternalBlue (CVE-2017-0144) — SMBv1 remote code execution",
                "explanation": (
                    "This host is vulnerable to EternalBlue: a flaw in SMBv1 "
                    "that lets an attacker run code on the machine without "
                    "any credentials. It was the flaw behind the WannaCry "
                    "ransomware outbreak."
                ),
                "remediation": [
                    "Install the Microsoft security update MS17-010 immediately.",
                    "Disable SMBv1 on every machine.",
                    "Block port 445 at the network boundary.",
                ],
                "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144"],
                "port": 445,
                "service": "microsoft-ds",
                "product": "",
                "cve": "CVE-2017-0144",
            })
    return findings


def analyse_scan(parsed):
    """Analyse a whole parsed scan. Returns a list of host results::

        {"address": ..., "hostnames": [...], "os": ..., "ports": [...],
         "findings": [...], "score": int, "breakdown": [...]}
    """
    results = []
    for host in parsed.get("hosts", []):
        findings = analyse_host(host)
        score, breakdown = score_for_findings(findings)
        results.append({
            "address": host.get("address"),
            "hostnames": host.get("hostnames", []),
            "os": host.get("os"),
            "ports": host.get("ports", []),
            "status": host.get("status"),
            "findings": findings,
            "score": score,
            "breakdown": breakdown,
        })
    return results


def scan_score(host_results):
    """Overall scan score: rounded mean of the host scores (100 if no hosts)."""
    if not host_results:
        return 100
    return round(sum(h["score"] for h in host_results) / len(host_results))


def count_by_severity(findings):
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f.get("severity", "Info")] = counts.get(f.get("severity", "Info"), 0) + 1
    return counts


def fix_first_list(all_findings):
    """Prioritised remediation list: Critical first, then High, Medium,
    Low, Info; duplicates (same title on different hosts) collapsed."""
    seen = set()
    ordered = []
    for sev in SEVERITY_ORDER:
        for f in all_findings:
            if f.get("severity") != sev:
                continue
            key = (f.get("title"), tuple(f.get("remediation", []))[:1])
            if key in seen:
                continue
            seen.add(key)
            ordered.append(f)
    return ordered

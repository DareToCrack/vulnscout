"""Seeded demo data: a fictional small-business network, run through the
real findings engine so the demo exercises the same code as a live scan.

Riverside Dental Clinic — three hosts, twelve findings, one Critical.
Nothing here is real: all addresses, hostnames and CVEs are illustrative.
"""

DEMO_TARGET = "192.168.1.0/24 (demo — Riverside Dental Clinic)"

DEMO_HOSTS = [
    {
        "address": "192.168.1.1",
        "address_type": "ipv4",
        "hostnames": ["gateway.local"],
        "status": "up",
        "os": {"name": "Linux 5.15 (OpenWrt)", "accuracy": 94},
        "ports": [
            {"port": 22, "protocol": "tcp", "state": "open",
             "service": {"name": "ssh", "product": "OpenSSH", "version": "8.9p1", "extrainfo": ""},
             "scripts": []},
            {"port": 53, "protocol": "tcp", "state": "open",
             "service": {"name": "domain", "product": "dnsmasq", "version": "2.86", "extrainfo": ""},
             "scripts": []},
            {"port": 80, "protocol": "tcp", "state": "open",
             "service": {"name": "http", "product": "uHTTPd", "version": "", "extrainfo": "router admin panel"},
             "scripts": []},
        ],
        "host_scripts": [],
    },
    {
        "address": "192.168.1.25",
        "address_type": "ipv4",
        "hostnames": ["fileserver.local"],
        "status": "up",
        "os": {"name": "Microsoft Windows Server 2016", "accuracy": 97},
        "ports": [
            {"port": 21, "protocol": "tcp", "state": "open",
             "service": {"name": "ftp", "product": "FileZilla Server", "version": "0.9.60", "extrainfo": ""},
             "scripts": []},
            {"port": 139, "protocol": "tcp", "state": "open",
             "service": {"name": "netbios-ssn", "product": "Microsoft Windows netbios-ssn", "version": "", "extrainfo": ""},
             "scripts": []},
            {"port": 445, "protocol": "tcp", "state": "open",
             "service": {"name": "microsoft-ds", "product": "Microsoft Windows Server 2016 microsoft-ds", "version": "", "extrainfo": ""},
             "scripts": []},
            {"port": 3389, "protocol": "tcp", "state": "open",
             "service": {"name": "ms-wbt-server", "product": "Microsoft Terminal Services", "version": "", "extrainfo": ""},
             "scripts": []},
        ],
        "host_scripts": [
            {"id": "smb-vuln-ms17-010", "output": (
                "  VULNERABLE:\n"
                "  Remote Code Execution vulnerability in Microsoft SMBv1 servers\n"
                "    State: VULNERABLE\n"
                "    IDs: CVE:CVE-2017-0143\n"
                "    Risk factor: HIGH")},
        ],
    },
    {
        "address": "192.168.1.40",
        "address_type": "ipv4",
        "hostnames": ["web.local"],
        "status": "up",
        "os": {"name": "Linux 5.4 (Ubuntu 20.04)", "accuracy": 96},
        "ports": [
            {"port": 80, "protocol": "tcp", "state": "open",
             "service": {"name": "http", "product": "Apache httpd", "version": "2.4.29", "extrainfo": ""},
             "scripts": [
                 {"id": "vulners", "output": (
                     "  cpe:/a:apache:http_server:2.4.29\n"
                     "    CVE-2022-22719\t5.3\thttps://vulners.com/cve/CVE-2022-22719")},
             ]},
            {"port": 443, "protocol": "tcp", "state": "open",
             "service": {"name": "https", "product": "Apache httpd", "version": "2.4.29", "extrainfo": ""},
             "scripts": []},
            {"port": 3306, "protocol": "tcp", "state": "open",
             "service": {"name": "mysql", "product": "MySQL", "version": "5.7.35", "extrainfo": ""},
             "scripts": []},
        ],
        "host_scripts": [],
    },
]


def demo_parsed():
    """Return the demo network in the same shape ``parse_nmap_xml`` returns."""
    return {"hosts": DEMO_HOSTS, "args": "nmap (demo data)", "version": "demo"}

"""Pure-Python parser for Nmap XML output (``nmap -oX -``).

No dependency on Nmap itself: the parser only needs the XML text, so it
is fully unit-testable with fixture files.
"""

import re
import xml.etree.ElementTree as ET

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
# A CVSS score printed next to a CVE id, e.g. "CVE-2021-44228\t10.0\t..."
CVE_SCORE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})\s+(\d{1,2}\.\d)")


def parse_vulners_output(output):
    """Extract CVE entries from a ``vulners`` NSE script output block.

    Returns a list of ``{"cve": ..., "score": float | None, "url": ...}``.
    The vulners script prints one CVE per line with its CVSS score when
    one is known; lines without a score still yield the CVE id.
    """
    cves = []
    seen = set()
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        m = CVE_SCORE_RE.search(line)
        if m:
            cve, score = m.group(1), float(m.group(2))
        else:
            m2 = CVE_RE.search(line)
            if not m2:
                continue
            cve, score = m2.group(0), None
        if cve in seen:
            continue
        seen.add(cve)
        url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + cve
        cves.append({"cve": cve, "score": score, "url": url})
    return cves


def _parse_scripts(elem):
    scripts = []
    if elem is None:
        return scripts
    for s in elem.findall("script"):
        scripts.append({"id": s.get("id", ""), "output": s.get("output", "")})
    return scripts


def parse_nmap_xml(xml_text):
    """Parse Nmap XML output into plain Python data.

    Returns ``{"hosts": [...], "args": ..., "version": ...}`` where each
    host has: address, address_type, hostnames, status, os (name/accuracy
    or None), ports (list of dicts with port/protocol/state/service/scripts)
    and host_scripts. Raises ``ValueError`` on malformed XML.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError("Could not parse Nmap XML output: %s" % exc) from exc

    hosts = []
    for h in root.findall("host"):
        status_el = h.find("status")
        status = status_el.get("state") if status_el is not None else "unknown"

        address, address_type = None, None
        for a in h.findall("address"):
            # Prefer the IPv4 address; keep the first of any type otherwise.
            if a.get("addrtype") == "ipv4":
                address, address_type = a.get("addr"), "ipv4"
                break
            if address is None:
                address, address_type = a.get("addr"), a.get("addrtype")

        hostnames = []
        hostnames_el = h.find("hostnames")
        if hostnames_el is not None:
            hostnames = [hn.get("name") for hn in hostnames_el.findall("hostname")
                         if hn.get("name")]

        os_name, os_accuracy = None, None
        os_el = h.find("os")
        if os_el is not None:
            for match in os_el.findall("osmatch"):
                if match.get("name"):
                    os_name = match.get("name")
                    try:
                        os_accuracy = int(match.get("accuracy", "0"))
                    except ValueError:
                        os_accuracy = 0
                    break

        ports = []
        ports_el = h.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                state_el = p.find("state")
                service_el = p.find("service")
                service = {}
                if service_el is not None:
                    service = {
                        "name": service_el.get("name", ""),
                        "product": service_el.get("product", ""),
                        "version": service_el.get("version", ""),
                        "extrainfo": service_el.get("extrainfo", ""),
                    }
                try:
                    port_no = int(p.get("portid", "0"))
                except ValueError:
                    port_no = 0
                ports.append({
                    "port": port_no,
                    "protocol": p.get("protocol", "tcp"),
                    "state": state_el.get("state") if state_el is not None else "unknown",
                    "service": service,
                    "scripts": _parse_scripts(p),
                })

        hosts.append({
            "address": address,
            "address_type": address_type,
            "hostnames": hostnames,
            "status": status,
            "os": {"name": os_name, "accuracy": os_accuracy} if os_name else None,
            "ports": ports,
            "host_scripts": _parse_scripts(h.find("hostscript")),
        })

    return {
        "hosts": hosts,
        "args": root.get("args", ""),
        "version": root.get("version", ""),
    }

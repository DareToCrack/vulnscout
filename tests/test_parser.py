"""Tests for the Nmap XML parser — no Nmap binary required."""

import os

import pytest

from vulnscout.parser import parse_nmap_xml, parse_vulners_output

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _read(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return f.read()


def test_parse_basic_host_fields():
    parsed = parse_nmap_xml(_read("scan_basic.xml"))
    assert parsed["version"] == "7.94"
    assert len(parsed["hosts"]) == 2
    host = parsed["hosts"][0]
    assert host["address"] == "192.168.1.10"
    assert host["address_type"] == "ipv4"
    assert host["hostnames"] == ["office-pc.local"]
    assert host["status"] == "up"
    assert host["os"]["name"] == "Linux 5.15"
    assert host["os"]["accuracy"] == 96


def test_parse_basic_ports_and_services():
    host = parse_nmap_xml(_read("scan_basic.xml"))["hosts"][0]
    ports = {p["port"]: p for p in host["ports"]}
    assert set(ports) == {22, 23, 80, 443}
    ssh = ports[22]
    assert ssh["state"] == "open"
    assert ssh["service"]["name"] == "ssh"
    assert ssh["service"]["product"] == "OpenSSH"
    assert ssh["service"]["version"] == "8.9p1"
    assert ssh["service"]["extrainfo"] == "Ubuntu"
    assert ports[443]["state"] == "closed"


def test_parse_port_scripts():
    host = parse_nmap_xml(_read("scan_basic.xml"))["hosts"][0]
    http = next(p for p in host["ports"] if p["port"] == 80)
    assert len(http["scripts"]) == 1
    assert http["scripts"][0]["id"] == "vulners"
    assert "CVE-2021-44790" in http["scripts"][0]["output"]


def test_parse_host_down():
    parsed = parse_nmap_xml(_read("scan_basic.xml"))
    down = parsed["hosts"][1]
    assert down["address"] == "192.168.1.11"
    assert down["status"] == "down"
    assert down["ports"] == []
    assert down["os"] is None


def test_parse_vuln_fixture_scripts():
    host = parse_nmap_xml(_read("scan_vuln.xml"))["hosts"][0]
    https = next(p for p in host["ports"] if p["port"] == 443)
    ids = [s["id"] for s in https["scripts"]]
    assert ids == ["ssl-heartbleed", "ssl-poodle", "vulners"]
    assert len(host["host_scripts"]) == 1
    assert host["host_scripts"][0]["id"] == "smb-vuln-ms17-010"
    filtered = next(p for p in host["ports"] if p["port"] == 22)
    assert filtered["state"] == "filtered"


def test_parse_vulners_output_with_and_without_scores():
    output = ("  cpe:/a:openssl:openssl:1.0.1f\n"
              "    CVE-2014-0160\t7.5\thttps://vulners.com/cve/CVE-2014-0160\n"
              "    CVE-2016-2107\t5.9\thttps://vulners.com/cve/CVE-2016-2107\n"
              "    CVE-2016-6304\n")
    cves = parse_vulners_output(output)
    assert [c["cve"] for c in cves] == ["CVE-2014-0160", "CVE-2016-2107", "CVE-2016-6304"]
    assert cves[0]["score"] == 7.5
    assert cves[1]["score"] == 5.9
    assert cves[2]["score"] is None
    assert cves[0]["url"].endswith("CVE-2014-0160")


def test_parse_vulners_output_dedupes():
    output = "CVE-2021-44228\t10.0\nCVE-2021-44228\t10.0\n"
    assert len(parse_vulners_output(output)) == 1


def test_parse_vulners_output_ignores_noise():
    assert parse_vulners_output("  cpe:/a:apache:http_server:2.4.29\n  no vulnerabilities here\n") == []


def test_parse_malformed_xml_raises():
    with pytest.raises(ValueError):
        parse_nmap_xml("<nmaprun><host><unclosed>")


def test_parse_empty_scan():
    parsed = parse_nmap_xml('<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"></nmaprun>')
    assert parsed["hosts"] == []

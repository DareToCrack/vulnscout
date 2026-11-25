"""Tests for the findings engine and scoring."""

import os

from vulnscout.findings import (analyse_scan, count_by_severity,
                               fix_first_list, scan_score, score_for_findings,
                               severity_from_cvss)
from vulnscout.parser import parse_nmap_xml

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _read(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return f.read()


def test_cvss_bands():
    assert severity_from_cvss(10.0) == "Critical"
    assert severity_from_cvss(9.0) == "Critical"
    assert severity_from_cvss(8.9) == "High"
    assert severity_from_cvss(7.0) == "High"
    assert severity_from_cvss(6.9) == "Medium"
    assert severity_from_cvss(4.0) == "Medium"
    assert severity_from_cvss(3.9) == "Low"
    assert severity_from_cvss(0.1) == "Low"
    assert severity_from_cvss(0.0) == "Info"
    assert severity_from_cvss(None) == "Medium"


def test_score_deductions_and_floor():
    findings = [
        {"severity": "Critical", "title": "a"},
        {"severity": "High", "title": "b"},
        {"severity": "Medium", "title": "c"},
        {"severity": "Low", "title": "d"},
        {"severity": "Info", "title": "e"},
    ]
    score, breakdown = score_for_findings(findings)
    assert score == 100 - 25 - 15 - 8 - 3 - 0
    assert [b["deduction"] for b in breakdown] == [25, 15, 8, 3, 0]
    assert breakdown[0]["title"] == "a"


def test_score_floors_at_zero():
    findings = [{"severity": "Critical", "title": str(i)} for i in range(10)]
    score, _ = score_for_findings(findings)
    assert score == 0


def test_score_no_findings_is_100():
    assert score_for_findings([]) == (100, [])


def test_scan_score_is_mean():
    assert scan_score([{"score": 90}, {"score": 70}, {"score": 80}]) == 80
    assert scan_score([]) == 100


def test_telnet_is_critical_and_ssh_is_low():
    parsed = parse_nmap_xml(_read("scan_basic.xml"))
    results = analyse_scan(parsed)
    up = results[0]
    port_findings = [f for f in up["findings"] if f.get("cve") is None]
    by_port = {f["port"]: f for f in port_findings}
    assert by_port[23]["severity"] == "Critical"
    assert "plain text" in by_port[23]["explanation"]
    assert by_port[22]["severity"] == "Low"
    assert by_port[80]["severity"] == "Info"


def test_vulners_cve_becomes_finding_with_cvss_severity():
    parsed = parse_nmap_xml(_read("scan_basic.xml"))
    results = analyse_scan(parsed)
    cves = [f for f in results[0]["findings"] if f.get("cve")]
    assert len(cves) == 1
    assert cves[0]["cve"] == "CVE-2021-44790"
    assert cves[0]["severity"] == "Critical"  # CVSS 9.8
    assert "44790" in cves[0]["references"][0]


def test_heartbleed_and_poodle_and_eternalblue():
    parsed = parse_nmap_xml(_read("scan_vuln.xml"))
    results = analyse_scan(parsed)
    titles = [f["title"] for f in results[0]["findings"]]
    assert any("Heartbleed" in t for t in titles)
    assert any("POODLE" in t for t in titles)
    assert any("EternalBlue" in t for t in titles)
    sev = {f["title"]: f["severity"] for f in results[0]["findings"]}
    assert sev[[t for t in titles if "Heartbleed" in t][0]] == "Critical"
    assert sev[[t for t in titles if "POODLE" in t][0]] == "Medium"
    assert sev[[t for t in titles if "EternalBlue" in t][0]] == "Critical"


def test_cve_without_score_defaults_to_medium():
    parsed = parse_nmap_xml(_read("scan_vuln.xml"))
    results = analyse_scan(parsed)
    f = next(f for f in results[0]["findings"] if f.get("cve") == "CVE-2016-6304")
    assert f["severity"] == "Medium"


def test_unknown_open_port_is_low_with_guidance():
    parsed = parse_nmap_xml(_read("scan_vuln.xml"))
    results = analyse_scan(parsed)
    f = next(f for f in results[0]["findings"] if f["port"] == 8080)
    assert f["severity"] == "Low"
    assert f["remediation"]


def test_closed_and_filtered_ports_produce_no_findings():
    parsed = parse_nmap_xml(_read("scan_vuln.xml"))
    results = analyse_scan(parsed)
    ports = [f["port"] for f in results[0]["findings"]]
    assert 22 not in ports  # filtered SSH must not be flagged


def test_down_host_produces_no_findings():
    parsed = parse_nmap_xml(_read("scan_basic.xml"))
    results = analyse_scan(parsed)
    assert results[1]["findings"] == []
    assert results[1]["score"] == 100


def test_every_finding_has_remediation_and_explanation():
    for name in ("scan_basic.xml", "scan_vuln.xml"):
        parsed = parse_nmap_xml(_read(name))
        for host in analyse_scan(parsed):
            for f in host["findings"]:
                assert f["explanation"].strip()
                assert f["remediation"], f["title"]
                assert f["severity"] in ("Critical", "High", "Medium", "Low", "Info")


def test_count_by_severity():
    findings = [{"severity": "Critical"}, {"severity": "High"},
                {"severity": "High"}, {"severity": "Info"}]
    counts = count_by_severity(findings)
    assert counts == {"Critical": 1, "High": 2, "Medium": 0, "Low": 0, "Info": 1}


def test_fix_first_ordering_and_dedup():
    findings = [
        {"severity": "Low", "title": "SSH is open", "remediation": ["Use keys"]},
        {"severity": "Critical", "title": "Telnet is open", "remediation": ["Disable it"]},
        {"severity": "Critical", "title": "Telnet is open", "remediation": ["Disable it"]},
        {"severity": "High", "title": "FTP is open", "remediation": ["Use SFTP"]},
    ]
    ordered = fix_first_list(findings)
    assert [f["severity"] for f in ordered] == ["Critical", "High", "Low"]
    assert len(ordered) == 3  # duplicate Telnet collapsed

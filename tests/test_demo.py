"""Tests for the demo data — the primary verifiable surface."""

from vulnscout.demo import DEMO_TARGET, demo_parsed
from vulnscout.findings import analyse_scan, count_by_severity, scan_score


def test_demo_has_three_hosts():
    parsed = demo_parsed()
    assert len(parsed["hosts"]) == 3
    assert {h["address"] for h in parsed["hosts"]} == {
        "192.168.1.1", "192.168.1.25", "192.168.1.40"}


def test_demo_has_exactly_one_critical():
    hosts = analyse_scan(demo_parsed())
    all_findings = [f for h in hosts for f in h["findings"]]
    counts = count_by_severity(all_findings)
    assert counts["Critical"] == 1
    assert len(all_findings) == 12
    assert counts == {"Critical": 1, "High": 4, "Medium": 2, "Low": 2, "Info": 3}


def test_demo_critical_is_eternalblue():
    hosts = analyse_scan(demo_parsed())
    criticals = [f for h in hosts for f in h["findings"]
                 if f["severity"] == "Critical"]
    assert len(criticals) == 1
    assert "EternalBlue" in criticals[0]["title"]
    assert criticals[0]["cve"] == "CVE-2017-0144"


def test_demo_host_scores():
    hosts = analyse_scan(demo_parsed())
    by_addr = {h["address"]: h for h in hosts}
    assert by_addr["192.168.1.1"]["score"] == 94   # 2 x Low
    assert by_addr["192.168.1.25"]["score"] == 22  # Critical + 3 High + Medium
    assert by_addr["192.168.1.40"]["score"] == 77  # High + Medium
    assert scan_score(hosts) == 64


def test_demo_target_label_marks_it_as_demo():
    assert "demo" in DEMO_TARGET.lower()

"""Tests for the Flask app: authorisation gate, demo flow, exports."""

import os
import tempfile

import pytest

from vulnscout.app import create_app


@pytest.fixture
def client():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    app = create_app(db_path=path, test_config={"TESTING": True})
    with app.test_client() as client:
        yield client
    os.unlink(path)


def _demo_scan(client):
    resp = client.post("/demo", follow_redirects=True)
    assert resp.status_code == 200
    return resp


def test_dashboard_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"VulnScout" in resp.data
    assert b"Load demo scan" in resp.data


def test_scan_page_loads_with_profiles(client):
    resp = client.get("/scan")
    assert resp.status_code == 200
    assert b"Quick" in resp.data
    assert b"Standard" in resp.data
    assert b"Deep" in resp.data
    assert b"written permission" in resp.data


def test_scan_refused_without_authorisation_checkbox(client):
    resp = client.post("/scan", data={"target": "127.0.0.1", "profile": "quick"})
    assert resp.status_code == 400
    assert b"Authorisation is required" in resp.data


def test_scan_refused_with_bad_target_even_when_authorised(client):
    resp = client.post("/scan", data={"target": "192.168.0.0/16",
                                      "profile": "quick", "authorised": "on"})
    assert resp.status_code == 400
    assert b"too large" in resp.data


def test_demo_scan_flow(client):
    resp = _demo_scan(client)
    assert b"Riverside Dental Clinic" in resp.data
    assert b"EternalBlue" in resp.data
    assert b"64" in resp.data  # overall posture score


def test_results_filter_by_severity(client):
    _demo_scan(client)
    resp = client.get("/scans/1?severity=Critical")
    assert resp.status_code == 200
    assert b"EternalBlue" in resp.data
    assert b"Telnet" not in resp.data  # demo has no Telnet finding
    resp = client.get("/scans/1?severity=High")
    assert b"FTP is open" in resp.data


def test_results_search(client):
    _demo_scan(client)
    resp = client.get("/scans/1?q=mysql")
    assert b"MySQL" in resp.data
    resp = client.get("/scans/1?q=zzzznotfound")
    assert b"No findings match" in resp.data


def test_host_detail_page(client):
    _demo_scan(client)
    resp = client.get("/scans/1/host/192.168.1.25")
    assert resp.status_code == 200
    assert b"192.168.1.25" in resp.data
    assert b"Score breakdown" in resp.data
    assert b"EternalBlue" in resp.data


def test_report_page(client):
    _demo_scan(client)
    resp = client.get("/scans/1/report")
    assert resp.status_code == 200
    assert b"Vulnerability scan report" in resp.data
    assert b"Fix first" in resp.data
    assert b"How the score works" in resp.data


def test_csv_export(client):
    _demo_scan(client)
    resp = client.get("/scans/1/export.csv")
    assert resp.status_code == 200
    assert resp.mimetype == "text/csv"
    assert b"host,severity,port,service,title,cve" in resp.data
    assert b"CVE-2017-0144" in resp.data
    assert len(resp.data.decode().strip().splitlines()) == 13  # header + 12 findings


def test_json_export(client):
    _demo_scan(client)
    resp = client.get("/scans/1/export.json")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["tool"] == "VulnScout"
    assert data["score"] == 64
    assert len(data["hosts"]) == 3


def test_history_and_delete(client):
    _demo_scan(client)
    resp = client.get("/history")
    assert resp.status_code == 200
    assert b"Riverside Dental Clinic" in resp.data
    resp = client.post("/scans/1/delete", follow_redirects=True)
    assert resp.status_code == 200
    assert b"Riverside Dental Clinic" not in resp.data


def test_missing_scan_404s(client):
    assert client.get("/scans/999").status_code == 404
    assert client.get("/scans/999/report").status_code == 404
    assert client.get("/scans/1/host/10.0.0.1").status_code == 404

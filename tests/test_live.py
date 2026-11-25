"""Live tests — require the real Nmap binary. Skipped when it is missing."""

import shutil
import subprocess
import sys

import pytest

from vulnscout.findings import analyse_scan, scan_score
from vulnscout.nmap_runner import run_scan
from vulnscout.parser import parse_nmap_xml

pytestmark = pytest.mark.skipif(
    shutil.which("nmap") is None, reason="nmap not installed")


def test_real_quick_scan_of_localhost():
    xml = run_scan("127.0.0.1", "quick", authorised=True)
    assert "<nmaprun" in xml
    parsed = parse_nmap_xml(xml)
    assert len(parsed["hosts"]) == 1
    host = parsed["hosts"][0]
    assert host["address"] == "127.0.0.1"
    assert host["status"] == "up"
    results = analyse_scan(parsed)
    assert results[0]["score"] <= 100
    assert isinstance(scan_score(results), int)


def test_cli_quick_scan_localhost_json():
    proc = subprocess.run(
        [sys.executable, "-m", "vulnscout", "scan", "127.0.0.1",
         "--profile", "quick", "--json", "-y"],
        capture_output=True, text=True, timeout=180, cwd=".")
    assert proc.returncode == 0, proc.stderr
    import json
    data = json.loads(proc.stdout)
    assert data["target"] == "127.0.0.1"
    assert data["score"] <= 100
    assert len(data["hosts"]) == 1

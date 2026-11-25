"""Tests for target validation and the authorisation gate."""

import pytest

from vulnscout.nmap_runner import PROFILES, run_scan, validate_target


def test_validate_single_ip():
    assert validate_target("192.168.1.1") == "192.168.1.1"
    assert validate_target("  10.0.0.5  ") == "10.0.0.5"
    assert validate_target("127.0.0.1") == "127.0.0.1"


def test_validate_hostname_and_domain():
    assert validate_target("example.com") == "example.com"
    assert validate_target("Office-PC.local") == "office-pc.local"


def test_validate_cidr_up_to_24():
    assert validate_target("192.168.1.0/24") == "192.168.1.0/24"
    assert validate_target("10.0.0.128/25") == "10.0.0.128/25"
    assert validate_target("192.168.1.5/32") == "192.168.1.5/32"


def test_reject_ranges_larger_than_24():
    with pytest.raises(ValueError, match="too large"):
        validate_target("192.168.0.0/16")
    with pytest.raises(ValueError, match="too large"):
        validate_target("10.0.0.0/8")


def test_reject_unspecified_and_multicast():
    with pytest.raises(ValueError):
        validate_target("0.0.0.0/0")
    with pytest.raises(ValueError):
        validate_target("224.0.0.1")
    with pytest.raises(ValueError):
        validate_target("0.0.0.0")


def test_reject_garbage():
    with pytest.raises(ValueError):
        validate_target("")
    with pytest.raises(ValueError):
        validate_target("not a host!!")
    with pytest.raises(ValueError):
        validate_target("192.168.1.999")
    with pytest.raises(ValueError):
        validate_target("example")
    with pytest.raises(ValueError):
        validate_target("192.168.1.1; rm -rf /")


def test_reject_ipv6():
    with pytest.raises(ValueError):
        validate_target("::1")


def test_profiles_exist():
    assert set(PROFILES) == {"quick", "standard", "deep"}
    for name, p in PROFILES.items():
        assert p["args"] and p["timeout"] > 0
        assert "-oX" not in p["args"]  # runner adds the XML flag itself


def test_run_scan_refuses_without_authorisation():
    with pytest.raises(PermissionError, match="authorisation"):
        run_scan("127.0.0.1", "quick", authorised=False)

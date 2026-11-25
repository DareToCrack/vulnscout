"""Nmap invocation: target validation, scan profiles, subprocess runner.

Safety rules (also enforced in the web UI):
* the caller must pass ``authorised=True`` — the runner refuses otherwise;
* targets are a single host/IP/domain or a CIDR no larger than /24;
* ranges such as 0.0.0.0/0, multicast and non-printable targets are rejected.
"""

import ipaddress
import re
import shutil
import subprocess

MAX_PREFIX = 24  # never scan a range larger than a /24

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

# All profiles use -sT (TCP connect scan) instead of the default SYN scan:
# it works without root / raw-socket privileges, which is what a small
# business running this on an ordinary workstation will have. OS
# detection (-O) still needs privileges; when it is unavailable Nmap
# skips it and the scan continues.

PROFILES = {
    "quick": {
        "label": "Quick",
        "description": "Top 100 ports with service and version detection. A few minutes.",
        "args": ["-T4", "-sT", "--top-ports", "100", "-sV"],
        "timeout": 300,
    },
    "standard": {
        "label": "Standard",
        "description": "Top 1,000 ports, service/version detection, OS detection and NSE vulnerability scripts. The recommended default.",
        "args": ["-T4", "-sT", "--top-ports", "1000", "-sV", "-O",
                 "--script", "vulners,ssl-heartbleed,ssl-poodle,http-vuln-cve2017-5638"],
        "timeout": 900,
    },
    "deep": {
        "label": "Deep",
        "description": "All 65,535 ports, service/version detection, OS detection and the full NSE vulnerability script suite. Slow — use overnight.",
        "args": ["-T4", "-sT", "-p-", "-sV", "-O", "--script", "vuln"],
        "timeout": 3600,
    },
}


def validate_target(target):
    """Validate and normalise a scan target.

    Accepts a single IPv4 address, a hostname/domain, or a CIDR network
    with a prefix of /24 or longer. Returns the normalised target string.
    Raises ``ValueError`` with a plain-language reason otherwise.
    """
    if not target or not isinstance(target, str):
        raise ValueError("Enter a target — a host, IP address or network range.")
    target = target.strip()
    if not target:
        raise ValueError("Enter a target — a host, IP address or network range.")
    if len(target) > 253:
        raise ValueError("Target is too long.")
    if any(ord(c) < 32 for c in target):
        raise ValueError("Target contains invalid characters.")

    # CIDR range, e.g. 192.168.1.0/24
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            raise ValueError("'%s' is not a valid network range." % target)
        if net.version != 4:
            raise ValueError("Only IPv4 networks are supported.")
        if net.prefixlen < MAX_PREFIX:
            raise ValueError(
                "That range is too large. VulnScout scans at most a /24 "
                "(256 addresses) at a time — scan one segment, then the next.")
        if net.is_multicast or net.is_reserved or net.is_unspecified:
            raise ValueError("'%s' is not a scannable network." % target)
        return str(net)

    # Single IPv4 address
    try:
        addr = ipaddress.ip_address(target)
        if addr.version != 4:
            raise ValueError("Only IPv4 addresses are supported.")
        if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
            raise ValueError("'%s' is not a scannable address." % target)
        return str(addr)
    except ValueError as exc:
        # Not an IP — it may be a hostname. Re-raise only our own errors.
        if "not a scannable" in str(exc) or "Only IPv4" in str(exc):
            raise
    # Looks like an IP address but isn't a valid one (e.g. 192.168.1.999):
    # reject it rather than treating it as a hostname.
    if re.fullmatch(r"[0-9.]+", target):
        raise ValueError("'%s' is not a valid IP address." % target)

    if HOSTNAME_RE.match(target) and "." in target:
        return target.lower()
    raise ValueError(
        "'%s' does not look like a host, IP address or network range." % target)


def profile_args(profile):
    """Return the nmap argument list for a profile name."""
    if profile not in PROFILES:
        raise ValueError("Unknown scan profile: %s" % profile)
    return list(PROFILES[profile]["args"])


def nmap_available():
    return shutil.which("nmap") is not None


def run_scan(target, profile="standard", authorised=False, timeout=None):
    """Run Nmap against a validated target and return the raw XML output.

    Raises ``PermissionError`` if ``authorised`` is False, ``ValueError``
    for a bad target/profile, ``RuntimeError`` if Nmap is missing, and
    ``TimeoutError`` if the scan runs past its profile timeout.
    """
    if not authorised:
        raise PermissionError(
            "Scan refused: authorisation is required. Confirm you own the "
            "target network or have written permission to scan it.")
    target = validate_target(target)
    if profile not in PROFILES:
        raise ValueError("Unknown scan profile: %s" % profile)
    if not nmap_available():
        raise RuntimeError(
            "Nmap is not installed. Install it first — see the README "
            "(apt install nmap, brew install nmap, or the Nmap download page).")

    args = ["nmap"] + profile_args(profile) + ["-oX", "-", target]
    limit = timeout or PROFILES[profile]["timeout"]
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=limit)
    except subprocess.TimeoutExpired:
        raise TimeoutError(
            "The %s scan of %s ran past its %d second limit and was stopped."
            % (profile, target, limit))
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(
            "Nmap exited with code %d: %s" % (proc.returncode, proc.stderr.strip()[:500]))
    return proc.stdout

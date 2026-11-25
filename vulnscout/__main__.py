"""VulnScout CLI: ``python -m vulnscout scan <target> --profile standard``"""

import argparse
import json
import sys

from .findings import SEVERITY_ORDER, analyse_scan, count_by_severity, scan_score
from .nmap_runner import PROFILES, run_scan, validate_target
from .parser import parse_nmap_xml


def cmd_scan(args):
    try:
        target = validate_target(args.target)
    except ValueError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 2
    if not args.yes:
        print("You are about to scan %s." % target)
        print("Only scan networks you own or have written permission to scan —")
        print("scanning without permission is illegal.")
        answer = input("Confirm you are authorised (type YES): ").strip()
        if answer != "YES":
            print("Scan cancelled.", file=sys.stderr)
            return 2
    try:
        xml = run_scan(target, args.profile, authorised=True)
    except (PermissionError, RuntimeError, TimeoutError) as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 1
    hosts = analyse_scan(parse_nmap_xml(xml))
    score = scan_score(hosts)
    all_findings = [f for h in hosts for f in h["findings"]]
    counts = count_by_severity(all_findings)

    if args.json:
        print(json.dumps({
            "target": target, "profile": args.profile, "score": score,
            "hosts": hosts}, indent=2, default=str))
        return 0

    print("=" * 60)
    print("VulnScout scan: %s (%s profile)" % (target, args.profile))
    print("Posture score: %d/100" % score)
    print("Findings: " + ", ".join(
        "%d %s" % (counts[s], s) for s in SEVERITY_ORDER))
    print("=" * 60)
    for host in hosts:
        print("\n%s  (%s) — score %d/100" % (
            host["address"],
            host["os"]["name"] if host["os"] else "OS unknown",
            host["score"]))
        for f in host["findings"]:
            print("  [%s] %s" % (f["severity"], f["title"]))
            if f.get("cve"):
                print("        %s" % f["cve"])
            print("        Fix: %s" % f["remediation"][0])
    if not all_findings:
        print("\nNo findings — nothing exposed that this scanner recognises.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="vulnscout",
        description="VulnScout — automated vulnerability scanner for small businesses.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan a host or network you are authorised to scan.")
    scan.add_argument("target", help="Host, IP, domain, or network up to /24")
    scan.add_argument("--profile", choices=list(PROFILES), default="standard",
                      help="Scan profile (default: standard)")
    scan.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    scan.add_argument("-y", "--yes", action="store_true",
                      help="Skip the interactive authorisation prompt (you must still be authorised)")
    scan.set_defaults(func=cmd_scan)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

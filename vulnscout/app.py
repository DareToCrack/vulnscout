"""VulnScout web app — Flask dashboard for automated vulnerability scans.

Scan flow: the new-scan form requires the authorisation checkbox
("I own this network or have written permission to scan it"); without it
the server refuses the scan with HTTP 400. Accepted scans run in a
background thread (Nmap is slow) and the results page refreshes until
the scan finishes.
"""

import os
import threading

from flask import (Flask, abort, jsonify, redirect, render_template,
                   request, url_for)

from . import db as store
from .demo import DEMO_TARGET, demo_parsed
from .findings import analyse_scan, count_by_severity, fix_first_list, scan_score
from .nmap_runner import PROFILES, nmap_available, run_scan, validate_target
from .parser import parse_nmap_xml

APP_DIR = os.path.dirname(os.path.abspath(__file__))


def create_app(db_path=None, test_config=None):
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path or os.path.join(
        os.path.dirname(APP_DIR), "data", "vulnscout.db")
    if test_config:
        app.config.update(test_config)
    store.init_db(app.config["DB_PATH"])

    def run_scan_job(scan_id, target, profile):
        """Background worker: run Nmap, parse, analyse, store."""
        try:
            xml = run_scan(target, profile, authorised=True)
            parsed = parse_nmap_xml(xml)
            hosts = analyse_scan(parsed)
            store.finish_scan(app.config["DB_PATH"], scan_id, hosts, scan_score(hosts))
        except Exception as exc:  # keep the failure visible in the UI
            store.fail_scan(app.config["DB_PATH"], scan_id, str(exc))

    @app.route("/")
    def dashboard():
        scans = store.list_scans(app.config["DB_PATH"], limit=10)
        latest = None
        for s in scans:
            if s["status"] == "complete":
                latest = store.get_scan(app.config["DB_PATH"], s["id"])
                break
        return render_template("dashboard.html", scans=scans, latest=latest,
                               nmap_available=nmap_available())

    @app.route("/scan", methods=["GET", "POST"])
    def new_scan():
        if request.method == "GET":
            return render_template("scan.html", profiles=PROFILES,
                                   nmap_available=nmap_available())
        # --- authorisation gate: the checkbox is mandatory ---
        if request.form.get("authorised") != "on":
            return render_template(
                "scan.html", profiles=PROFILES, nmap_available=nmap_available(),
                error="Authorisation is required. Tick the box confirming you "
                      "own this network or have written permission to scan it — "
                      "scanning a network without permission is illegal."), 400
        target_raw = request.form.get("target", "").strip()
        profile = request.form.get("profile", "standard")
        if profile not in PROFILES:
            profile = "standard"
        try:
            target = validate_target(target_raw)
        except ValueError as exc:
            return render_template(
                "scan.html", profiles=PROFILES, nmap_available=nmap_available(),
                error=str(exc), target=target_raw), 400
        if not nmap_available():
            return render_template(
                "scan.html", profiles=PROFILES, nmap_available=nmap_available(),
                error="Nmap is not installed on this machine. Install it first "
                      "(see the README), or use the demo scan."), 400
        scan_id = store.create_scan(app.config["DB_PATH"], target, profile)
        thread = threading.Thread(target=run_scan_job,
                                  args=(scan_id, target, profile), daemon=True)
        thread.start()
        return redirect(url_for("scan_results", scan_id=scan_id))

    @app.route("/demo", methods=["POST"])
    def demo_scan():
        """Load the seeded demo scan (no Nmap, no network access)."""
        scan_id = store.create_scan(app.config["DB_PATH"], DEMO_TARGET,
                                    "standard", is_demo=True)
        hosts = analyse_scan(demo_parsed())
        store.finish_scan(app.config["DB_PATH"], scan_id, hosts, scan_score(hosts))
        return redirect(url_for("scan_results", scan_id=scan_id))

    @app.route("/scans/<int:scan_id>")
    def scan_results(scan_id):
        scan = store.get_scan(app.config["DB_PATH"], scan_id)
        if scan is None:
            abort(404)
        severity = request.args.get("severity", "")
        query = request.args.get("q", "").strip().lower()
        findings = scan["findings"]
        if severity:
            findings = [f for f in findings if f.get("severity") == severity]
        if query:
            findings = [f for f in findings
                        if query in (f.get("title", "") + " " +
                                     f.get("explanation", "") + " " +
                                     (f.get("cve") or "")).lower()]
        counts = count_by_severity(scan["findings"])
        fix_first = fix_first_list(scan["findings"])
        host_map = {h["address"]: h for h in scan["hosts"]}
        return render_template("results.html", scan=scan, findings=findings,
                               counts=counts, fix_first=fix_first,
                               host_map=host_map, severity=severity, query=query)

    @app.route("/scans/<int:scan_id>/host/<address>")
    def host_detail(scan_id, address):
        scan = store.get_scan(app.config["DB_PATH"], scan_id)
        if scan is None:
            abort(404)
        host = next((h for h in scan["hosts"] if h["address"] == address), None)
        if host is None:
            abort(404)
        return render_template("host.html", scan=scan, host=host)

    @app.route("/scans/<int:scan_id>/report")
    def report(scan_id):
        scan = store.get_scan(app.config["DB_PATH"], scan_id)
        if scan is None:
            abort(404)
        counts = count_by_severity(scan["findings"])
        return render_template("report.html", scan=scan, counts=counts,
                               fix_first=fix_first_list(scan["findings"]))

    @app.route("/scans/<int:scan_id>/export.csv")
    def export_csv(scan_id):
        import csv
        import io
        scan = store.get_scan(app.config["DB_PATH"], scan_id)
        if scan is None:
            abort(404)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["host", "severity", "port", "service", "title", "cve",
                    "explanation", "remediation"])
        for f in scan["findings"]:
            w.writerow([f.get("host", ""), f.get("severity"), f.get("port"),
                        f.get("service"), f.get("title"), f.get("cve") or "",
                        f.get("explanation"), " | ".join(f.get("remediation", []))])
        return app.response_class(
            buf.getvalue(), mimetype="text/csv",
            headers={"Content-Disposition":
                     "attachment; filename=vulnscout-scan-%d.csv" % scan_id})

    @app.route("/scans/<int:scan_id>/export.json")
    def export_json(scan_id):
        scan = store.get_scan(app.config["DB_PATH"], scan_id)
        if scan is None:
            abort(404)
        return jsonify({
            "tool": "VulnScout", "target": scan["target"],
            "profile": scan["profile"], "score": scan["score"],
            "started_at": scan["started_at"], "finished_at": scan["finished_at"],
            "hosts": scan["hosts"],
        })

    @app.route("/history")
    def history():
        return render_template("history.html",
                               scans=store.list_scans(app.config["DB_PATH"], limit=50))

    @app.route("/scans/<int:scan_id>/delete", methods=["POST"])
    def delete(scan_id):
        store.delete_scan(app.config["DB_PATH"], scan_id)
        return redirect(url_for("history"))

    return app


def main():
    app = create_app()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    print("VulnScout running at http://%s:%d" % (host, port))
    if not nmap_available():
        print("WARNING: nmap is not installed — live scans are disabled. "
              "Demo scans still work.")
    app.run(host=host, port=port)

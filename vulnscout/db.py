"""SQLite storage for scan history: one row per scan, with hosts and
findings stored as JSON so a whole scan round-trips in a few queries.
"""

import json
import os
import sqlite3
from datetime import datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    profile TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    score INTEGER,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    is_demo INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    hosts_json TEXT,
    findings_json TEXT
);
"""


def connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db(db_path):
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = connect(db_path)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def _now():
    return datetime.now().isoformat(timespec="seconds")


def create_scan(db_path, target, profile, is_demo=False):
    conn = connect(db_path)
    cur = conn.execute(
        "INSERT INTO scans (target, profile, status, started_at, is_demo) "
        "VALUES (?, ?, 'running', ?, ?)",
        (target, profile, _now(), 1 if is_demo else 0))
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def finish_scan(db_path, scan_id, host_results, score):
    conn = connect(db_path)
    all_findings = []
    for h in host_results:
        for f in h["findings"]:
            item = dict(f)
            item["host"] = h["address"]
            all_findings.append(item)
    conn.execute(
        "UPDATE scans SET status='complete', score=?, finished_at=?, "
        "hosts_json=?, findings_json=? WHERE id=?",
        (score, _now(), json.dumps(host_results), json.dumps(all_findings), scan_id))
    conn.commit()
    conn.close()


def fail_scan(db_path, scan_id, error):
    conn = connect(db_path)
    conn.execute(
        "UPDATE scans SET status='failed', finished_at=?, error=? WHERE id=?",
        (_now(), error, scan_id))
    conn.commit()
    conn.close()


def get_scan(db_path, scan_id):
    conn = connect(db_path)
    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    scan = dict(row)
    scan["hosts"] = json.loads(row["hosts_json"]) if row["hosts_json"] else []
    scan["findings"] = json.loads(row["findings_json"]) if row["findings_json"] else []
    return scan


def list_scans(db_path, limit=20):
    conn = connect(db_path)
    rows = conn.execute(
        "SELECT id, target, profile, status, score, started_at, finished_at, "
        "is_demo FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_scan(db_path, scan_id):
    conn = connect(db_path)
    conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    conn.commit()
    conn.close()

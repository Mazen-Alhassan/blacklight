"""Scorer tests: status decisions and FP counting against an in-memory DB."""
import sqlite3
import tempfile

from harness import schema
from engine.engine import CompiledRule
from scoring.scorer import score_rule, _decide_status


def _db_with(events, windows):
    fd, path = tempfile.mkstemp(suffix=".db")
    conn = sqlite3.connect(path)
    schema.init_db(conn)
    for w in windows:
        conn.execute(
            "INSERT INTO windows (window_id,session_id,kind,name,technique,variant,"
            "ts_start,ts_end,root_pid,exit_code,ok) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (w["window_id"], "s", w["kind"], w["name"], w.get("technique"), None,
             w["ts_start"], w["ts_end"], 1, 0, w["ok"]))
    for e in events:
        conn.execute(
            "INSERT INTO events (ts,audit_id,category,exe,cmdline,session_id,"
            "window_id,in_lab,raw,username) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (e["ts"], 1, "process_creation", e["exe"], e["cmdline"], "s",
             e["window_id"], 1, "raw", "admin"))
    conn.commit()
    conn.row_factory = sqlite3.Row
    return conn


def _rule():
    cr = CompiledRule(id="r", title="t", file="f", attack=["T1059.004"],
                      tactics=["TA0002"], level="medium", logsource="linux",
                      category="process_creation", fields=["exe", "cmdline"])
    cr.buildable = True
    cr.where_sql = "exe LIKE '%/sh' ESCAPE '\\' AND cmdline LIKE '%-c%' ESCAPE '\\'"
    return cr


def test_validated_when_fires_everywhere_and_quiet():
    windows = [
        {"window_id": "a1", "kind": "attack", "name": "T1059.004-1",
         "technique": "T1059.004", "ts_start": 0.0, "ts_end": 9.0, "ok": 1},
        {"window_id": "a2", "kind": "attack", "name": "T1059.004-1",
         "technique": "T1059.004", "ts_start": 10.0, "ts_end": 19.0, "ok": 1},
        {"window_id": "b1", "kind": "benign", "name": "x",
         "technique": None, "ts_start": 20.0, "ts_end": 29.0, "ok": 1},
    ]
    events = [
        {"ts": 1.0, "exe": "/usr/bin/sh", "cmdline": "sh -c id", "window_id": "a1"},
        {"ts": 11.0, "exe": "/usr/bin/sh", "cmdline": "sh -c id", "window_id": "a2"},
        {"ts": 21.0, "exe": "/usr/bin/ls", "cmdline": "ls -la", "window_id": "b1"},
    ]
    conn = _db_with(events, windows)
    r = score_rule(conn, _rule(), [dict(w) for w in conn.execute("SELECT * FROM windows")], 0.01)
    assert r["true_positives"] == 2
    assert r["missed"] == 0
    assert r["false_positives"] == 0
    assert r["status"] == "validated"
    assert r["median_latency_ms"] is not None


def test_noisy_when_fp_over_threshold():
    windows = [{"window_id": "a1", "kind": "attack", "name": "T1059.004-1",
                "technique": "T1059.004", "ts_start": 0.0, "ts_end": 9.0, "ok": 1}]
    windows += [{"window_id": f"b{i}", "kind": "benign", "name": "x",
                 "technique": None, "ts_start": 10.0 + i, "ts_end": 10.5 + i, "ok": 1}
                for i in range(10)]
    events = [{"ts": 1.0, "exe": "/usr/bin/sh", "cmdline": "sh -c id", "window_id": "a1"}]
    # fires in 3 of 10 benign windows -> fp_rate 0.30
    events += [{"ts": 10.1 + i, "exe": "/usr/bin/sh", "cmdline": "sh -c x", "window_id": f"b{i}"}
               for i in range(3)]
    conn = _db_with(events, windows)
    r = score_rule(conn, _rule(), [dict(w) for w in conn.execute("SELECT * FROM windows")], 0.01)
    assert r["true_positives"] == 1
    assert r["false_positives"] == 3
    assert abs(r["fp_rate"] - 0.3) < 1e-9
    assert r["status"] == "noisy"


def test_status_matrix():
    assert _decide_status({"attack_windows": 0, "true_positives": 0, "fp_rate": None}, 0.01) == "untested"
    assert _decide_status({"attack_windows": 2, "true_positives": 2, "fp_rate": 0.0}, 0.01) == "validated"
    assert _decide_status({"attack_windows": 2, "true_positives": 2, "fp_rate": 0.5}, 0.01) == "noisy"
    assert _decide_status({"attack_windows": 2, "true_positives": 1, "fp_rate": 0.0}, 0.01) == "partial"
    assert _decide_status({"attack_windows": 2, "true_positives": 0, "fp_rate": 0.0}, 0.01) == "unfirable"

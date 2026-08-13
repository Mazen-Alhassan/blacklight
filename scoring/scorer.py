"""Score every rule against the telemetry: does it fire on its technique, how
often does it fire on benign activity, and how deep into the attack does it sit.

The scorer reads only the database and the compiled rules. It writes results.json.
It does not touch the sensor and it does not tune rules.
"""
import json
import sqlite3
import statistics
from datetime import datetime, timezone

# Precedence when collapsing several rules' statuses onto one technique cell.
STATUS_ORDER = ["validated", "partial", "noisy", "unfirable", "broken", "untested"]

TACTIC_NAMES = {
    "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
    "TA0004": "Privilege Escalation", "TA0005": "Defense Evasion",
    "TA0006": "Credential Access", "TA0007": "Discovery", "TA0008": "Lateral Movement",
    "TA0009": "Collection", "TA0011": "Command and Control", "TA0010": "Exfiltration",
    "TA0040": "Impact",
}


def _technique_matches(rule_techs, window_tech):
    if not window_tech:
        return False
    for rt in rule_techs:
        if rt == window_tech:
            return True
        base_r, base_w = rt.split(".")[0], window_tech.split(".")[0]
        if base_r == base_w:  # T1059 matches T1059.004 and vice versa
            return True
    return False


def _run_where(conn, where_sql, extra):
    """Return (match_count, earliest_ts) for events under a WHERE clause + extra."""
    sql = (f"SELECT COUNT(*), MIN(ts) FROM events "
           f"WHERE in_lab=1 AND {extra} AND ({where_sql})")
    cur = conn.execute(sql)
    n, mn = cur.fetchone()
    return n or 0, mn


def score_rule(conn, cr, windows, threshold):
    """cr is a CompiledRule. windows is the list of window rows (dicts)."""
    result = {
        "id": cr.id, "title": cr.title, "file": cr.file,
        "attack": cr.attack, "tactics": cr.tactics, "level": cr.level,
        "logsource": cr.logsource,
        "status": None, "broken_reason": None, "unmapped_fields": cr.unmapped_fields,
        "atomics": [], "attack_windows": 0, "true_positives": 0, "missed": 0,
        "benign_windows": 0, "false_positives": 0, "fp_rate": None,
        "median_latency_ms": None, "fp_examples": [], "evasions": [],
    }

    attack_windows = [w for w in windows if w["kind"] == "attack" and w["ok"]
                      and _technique_matches(cr.attack, w["technique"])]
    benign_windows = [w for w in windows if w["kind"] == "benign" and w["ok"]]
    result["attack_windows"] = len(attack_windows)
    result["benign_windows"] = len(benign_windows)
    result["atomics"] = sorted({w["name"] for w in attack_windows})

    # Broken: unmapped field or a conversion failure. No query is run.
    if cr.unmapped_fields or not cr.buildable:
        result["status"] = "broken"
        if cr.unmapped_fields:
            result["broken_reason"] = "unmapped fields: " + ", ".join(cr.unmapped_fields)
        else:
            result["broken_reason"] = cr.error or "rule did not compile"
        return result

    cat_filter = f"category='{cr.category}'" if cr.category else "1=1"

    # True positives and latency.
    latencies = []
    for w in attack_windows:
        try:
            n, mn = _run_where(conn, cr.where_sql,
                               f"window_id='{w['window_id']}' AND {cat_filter}")
        except sqlite3.Error as exc:
            result["status"] = "broken"
            result["broken_reason"] = f"query error: {exc}"
            return result
        if n > 0:
            result["true_positives"] += 1
            if mn is not None:
                latencies.append((mn - w["ts_start"]) * 1000.0)
        else:
            result["missed"] += 1
    if latencies:
        result["median_latency_ms"] = round(statistics.median(latencies), 1)

    # False positives across benign windows.
    fp_examples = []
    for w in benign_windows:
        try:
            n, _ = _run_where(conn, cr.where_sql,
                              f"window_id='{w['window_id']}' AND {cat_filter}")
        except sqlite3.Error:
            n = 0
        if n > 0:
            result["false_positives"] += 1
            if len(fp_examples) < 3:
                row = conn.execute(
                    f"SELECT cmdline, exe, raw FROM events WHERE in_lab=1 AND "
                    f"window_id='{w['window_id']}' AND {cat_filter} AND ({cr.where_sql}) LIMIT 1"
                ).fetchone()
                if row:
                    fp_examples.append({"window": w["name"], "cmdline": row[0], "exe": row[1]})
    result["fp_examples"] = fp_examples
    if benign_windows:
        result["fp_rate"] = result["false_positives"] / len(benign_windows)

    # Status.
    result["status"] = _decide_status(result, threshold)

    # Evasion pass: for a rule that fires, did the adversary variants slip past it?
    if result["status"] in ("validated", "partial", "noisy"):
        for w in windows:
            if w["kind"] != "evasion" or not w["ok"]:
                continue
            if not _technique_matches(cr.attack, w["technique"]):
                continue
            try:
                n, _ = _run_where(conn, cr.where_sql,
                                  f"window_id='{w['window_id']}' AND {cat_filter}")
            except sqlite3.Error:
                n = 0
            result["evasions"].append(
                {"variant": w["variant"], "atomic": w["name"], "evaded": n == 0})
    return result


def _decide_status(r, threshold):
    aw, tp = r["attack_windows"], r["true_positives"]
    fp_rate = r["fp_rate"] if r["fp_rate"] is not None else 0.0
    if aw == 0:
        return "untested"
    if tp == aw:
        return "validated" if fp_rate <= threshold else "noisy"
    if tp > 0:
        return "partial"
    return "unfirable"


def build_coverage(rule_results):
    tactics = {}
    for r in rule_results:
        for tech in r["attack"]:
            tacs = r["tactics"] or ["TA0000"]
            for ta in tacs:
                tactics.setdefault(ta, {"name": TACTIC_NAMES.get(ta, ta), "techniques": {}})
                cell = tactics[ta]["techniques"].setdefault(tech, {"status": "untested", "rules": 0})
                cell["rules"] += 1
                if STATUS_ORDER.index(r["status"]) < STATUS_ORDER.index(cell["status"]):
                    cell["status"] = r["status"]
    return {"tactics": tactics}


def build_worst_offenders(rule_results):
    scored = [r for r in rule_results if r["status"] in ("validated", "noisy", "partial")]
    def key(r):
        return -(r["fp_rate"] or 0)
    rows = []
    # one clean shipper, one noisy, one broken, to tell the story
    validated = sorted([r for r in scored if r["status"] == "validated"],
                       key=lambda r: (r["fp_rate"] or 0))
    noisy = sorted([r for r in scored if r["status"] == "noisy"],
                   key=lambda r: -(r["fp_rate"] or 0))
    broken = [r for r in rule_results if r["status"] == "broken"]
    picks = []
    if validated:
        picks.append(validated[0])
    if noisy:
        picks.append(noisy[0])
    if broken:
        picks.append(broken[0])
    for r in picks:
        fires = f"{r['true_positives']}/{r['attack_windows']}" if r["attack_windows"] else "-"
        if r["status"] == "broken":
            verdict, fp = "broken, field missing", "-"
        elif r["status"] == "noisy":
            verdict, fp = "too noisy", f"{(r['fp_rate'] or 0)*100:.2f}%"
        else:
            verdict, fp = "ship it", f"{(r['fp_rate'] or 0)*100:.2f}%"
        rows.append({"rule": r["id"], "fires": fires, "fp_rate": fp, "verdict": verdict})
    return rows


def score_all(db_path, compiled_rules, session_id, lab_meta, threshold=0.01):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    wrows = conn.execute("SELECT * FROM windows WHERE session_id=?", (session_id,)).fetchall()
    windows = [dict(w) for w in wrows]

    counts = conn.execute(
        "SELECT COUNT(*), SUM(in_lab) FROM events WHERE session_id=?", (session_id,)
    ).fetchone()
    events_total, events_in_lab = counts[0] or 0, counts[1] or 0

    rule_results = [score_rule(conn, cr, windows, threshold) for cr in compiled_rules]
    conn.close()

    kinds = {}
    for w in windows:
        if w["ok"]:
            kinds[w["kind"]] = kinds.get(w["kind"], 0) + 1

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lab": lab_meta,
        "run": {
            "session_id": session_id,
            "events_total": events_total,
            "events_in_lab": events_in_lab,
            "attack_windows": kinds.get("attack", 0),
            "benign_windows": kinds.get("benign", 0),
            "evasion_windows": kinds.get("evasion", 0),
            "noise_threshold": threshold,
        },
        "rules": rule_results,
        "coverage": build_coverage(rule_results),
        "worst_offenders": build_worst_offenders(rule_results),
    }

"""Orchestrator. One command: stand up the lab, run atomics and benign activity,
collect telemetry, score every rule, write data/results.json.

    python -m harness.run --rules rules/candidate --out data/results.json

Nothing here interprets telemetry or rules. It sequences the modules that do.
"""
import argparse
import glob
import json
import os
import subprocess
import sys

from harness import lab, executor, normalizer, library
from engine.engine import compile_rule
from scoring.scorer import score_all

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build_activities(attack_reps, benign_count, with_evasions):
    activities = []
    for a in library.load_atomics():
        for _ in range(attack_reps):
            activities.append({
                "kind": "attack", "name": a["id"], "command": a["command"],
                "user": a["user"], "technique": a["technique"], "variant": None,
            })
        if with_evasions:
            for v in a.get("variants", []):
                activities.append({
                    "kind": "evasion", "name": a["id"], "command": v["command"],
                    "user": a["user"], "technique": a["technique"], "variant": v["name"],
                })
    if benign_count:
        from harness.noise import generate_benign
        activities += generate_benign(benign_count)
    return activities


def lab_meta():
    def sx(*c):
        return subprocess.run(["docker", "exec", "lab-sensor", *c],
                              capture_output=True, text=True).stdout.strip()
    return {
        "sensor": "auditd",
        "kernel": sx("uname", "-r"),
        "arch": sx("uname", "-m"),
        "target_image": "lab-target:1",
        "audit_lost": None,
    }


def compile_rules(rules_dir):
    compiled = []
    for path in sorted(glob.glob(os.path.join(rules_dir, "*.yml")) +
                       glob.glob(os.path.join(rules_dir, "*.yaml"))):
        try:
            compiled.append(compile_rule(path))
        except Exception as exc:
            print(f"[warn] failed to load {path}: {exc}", file=sys.stderr)
    return compiled


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default="rules/candidate")
    ap.add_argument("--out", default="data/results.json")
    ap.add_argument("--attack-reps", type=int, default=2)
    ap.add_argument("--benign", type=int, default=0)
    ap.add_argument("--evasions", action="store_true")
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--keep-lab", action="store_true")
    ap.add_argument("--threshold", type=float, default=0.01)
    ap.add_argument("--session", default=None)
    args = ap.parse_args()

    os.makedirs(os.path.join(ROOT, "data"), exist_ok=True)
    db_path = os.path.join(ROOT, "data", "telemetry.db")
    windows_path = os.path.join(ROOT, "data", "windows.jsonl")
    snap_path = os.path.join(ROOT, "data", "session_audit.log")
    session_id = args.session or f"s-{os.urandom(3).hex()}"

    print(f"[run] session {session_id}")
    print("[run] bringing lab up ...")
    lab.up(build=not args.no_build)

    meta = lab_meta()
    uid_map = lab.uid_map()
    print(f"[run] lab ready: kernel {meta['kernel']} {meta['arch']}")

    # The log was reset before the sensor started (see lab.up), so no mid-session
    # truncate is needed here.
    activities = build_activities(args.attack_reps, args.benign, args.evasions)
    print(f"[run] executing {len(activities)} windows ...")
    executor.run_all(activities, windows_path)

    lost = lab.audit_lost()  # read loss counter before stopping auditd
    meta["audit_lost"] = lost
    nbytes = lab.flush_and_read(snap_path)
    print(f"[run] collected {nbytes} bytes of audit log, kernel lost={lost}")
    if lost != 0:
        print(f"[run] FAIL: kernel dropped {lost} audit events, measurement is unsound",
              file=sys.stderr)
        if not args.keep_lab:
            lab.down()
        sys.exit(2)

    print("[run] normalizing ...")
    stats = normalizer.normalize(snap_path, windows_path, session_id, db_path, uid_map)
    print(f"[run] events {stats['events_total']} total, {stats['events_in_lab']} in-lab, "
          f"windows {stats['windows_ok']}/{stats['windows_total']} ok")

    print("[run] compiling rules ...")
    compiled = compile_rules(args.rules)
    print(f"[run] {len(compiled)} rules compiled")

    print("[run] scoring ...")
    results = score_all(db_path, compiled, session_id, meta, threshold=args.threshold)
    with open(args.out, "w") as fh:
        json.dump(results, fh, indent=2)
    print(f"[run] wrote {args.out}")

    _summary(results)

    if not args.keep_lab:
        print("[run] tearing lab down ...")
        lab.down()


def _summary(results):
    from collections import Counter
    c = Counter(r["status"] for r in results["rules"])
    print("[run] status breakdown:", dict(c))
    for r in results["rules"]:
        fr = f"{r['fp_rate']*100:.2f}%" if r["fp_rate"] is not None else "-"
        print(f"       {r['status']:10s} {r['id']:40s} "
              f"fires {r['true_positives']}/{r['attack_windows']} fp {fr}")


if __name__ == "__main__":
    main()

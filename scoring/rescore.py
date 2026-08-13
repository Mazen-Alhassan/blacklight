"""Re-score the committed telemetry without touching Docker.

data/telemetry.db holds a full run's events and windows, so scoring can be redone
against it after a rule changes, or after the scorer itself changes, without
standing the lab back up. Handy for iterating on rules and for CI to prove the
committed results.json is reproducible from the committed database.

    python -m scoring.rescore --rules rules/candidate --out data/results.json
"""
import argparse
import glob
import json
import os

from engine.engine import compile_rule
from scoring.scorer import score_all

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default="rules/candidate")
    ap.add_argument("--db", default="data/telemetry.db")
    ap.add_argument("--out", default="data/results.json")
    ap.add_argument("--prior", default="data/results.json",
                    help="prior results.json to reuse lab meta and session id from")
    ap.add_argument("--threshold", type=float, default=0.01)
    args = ap.parse_args()

    prior = json.load(open(args.prior))
    session_id = prior["run"]["session_id"]
    lab_meta = prior["lab"]

    compiled = [compile_rule(p) for p in sorted(glob.glob(os.path.join(args.rules, "*.yml")))]
    results = score_all(args.db, compiled, session_id, lab_meta, threshold=args.threshold)
    with open(args.out, "w") as fh:
        json.dump(results, fh, indent=2)
    print(f"rescored {len(compiled)} rules from {args.db} -> {args.out}")


if __name__ == "__main__":
    main()

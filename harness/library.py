"""Load atomic tests and benign profiles from disk.

Atomic file (harness/atomics/*.yml):

    technique: T1059.004
    name: Unix Shell
    tactics: [TA0002]
    atomics:
      - id: T1059.004-1
        name: Command execution via sh -c
        user: admin            # admin | root
        command: sh -c 'id; whoami'
        variants:              # optional, used by the adversary pass
          - name: renamed_binary
            command: cp /bin/sh /tmp/x && /tmp/x -c 'id'
"""
import glob
import os

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ATOMICS_DIR = os.path.join(ROOT, "harness", "atomics")
BENIGN_DIR = os.path.join(ROOT, "harness", "profiles", "benign")


def load_atomics():
    """Return a flat list of atomic dicts, each with technique/tactics attached."""
    out = []
    for path in sorted(glob.glob(os.path.join(ATOMICS_DIR, "*.yml")) +
                       glob.glob(os.path.join(ATOMICS_DIR, "*.yaml"))):
        with open(path) as fh:
            docs = [d for d in yaml.safe_load_all(fh) if d]
        for doc in docs:
          for a in doc.get("atomics", []):
            out.append({
                "id": a["id"],
                "name": a.get("name", a["id"]),
                "technique": doc["technique"],
                "tactics": doc.get("tactics", []),
                "user": a.get("user", "admin"),
                "command": a["command"],
                "variants": a.get("variants", []),
                "needs": a.get("needs", []),
            })
    return out


def load_benign():
    out = []
    for path in sorted(glob.glob(os.path.join(BENIGN_DIR, "*.yml")) +
                       glob.glob(os.path.join(BENIGN_DIR, "*.yaml"))):
        with open(path) as fh:
            doc = yaml.safe_load(fh)
        out.append(doc)
    return out

"""Normalizer tests: process-tree window scoping is the subtle part.

A crafted audit log with one window and a piece of unrelated Docker noise proves
the scoper includes the activity subtree and excludes both the wrapper bash and
events that do not descend from it.
"""
import json
import os
import sqlite3
import tempfile

from harness.normalizer import normalize


def _syscall(ts, serial, pid, ppid, comm, exe, key="lab_exec", uid=1000):
    return (f'type=SYSCALL msg=audit({ts}:{serial}): arch=c000003e syscall=59 '
            f'success=yes exit=0 ppid={ppid} pid={pid} auid=4294967295 uid={uid} '
            f'gid={uid} euid={uid} ses=1 tty=(none) comm="{comm}" exe="{exe}" key="{key}"')


def _execve(ts, serial, argv):
    args = " ".join(f'a{i}="{a}"' for i, a in enumerate(argv))
    return f'type=EXECVE msg=audit({ts}:{serial}): argc={len(argv)} {args}'


def _fixture():
    # Window root: bash pid 1000 (the wrapper). Sentinels and activity are children.
    lines = [
        # unrelated Docker noise: pid 2000, parent 999, NOT under the wrapper
        _syscall(99.0, 1, 2000, 999, "runc", "/usr/bin/runc", uid=0),
        _execve(99.0, 1, ["runc", "init"]),
        # wrapper bash itself (must be excluded from scoring)
        _syscall(100.0, 2, 1000, 500, "bash", "/usr/bin/bash"),
        _execve(100.0, 2, ["bash", "-c", "true LWSTART; sh -c id; true LWEND"]),
        # start sentinel
        _syscall(100.05, 3, 1001, 1000, "true", "/usr/bin/true"),
        _execve(100.05, 3, ["/bin/true", "__LWSTART_aaaa__"]),
        # the activity: sh -c id  (this is what should be counted)
        _syscall(100.10, 4, 1002, 1000, "sh", "/usr/bin/dash"),
        _execve(100.10, 4, ["sh", "-c", "id"]),
        # a grandchild of the activity
        _syscall(100.12, 5, 1003, 1002, "id", "/usr/bin/id"),
        _execve(100.12, 5, ["id"]),
        # end sentinel
        _syscall(100.20, 6, 1004, 1000, "true", "/usr/bin/true"),
        _execve(100.20, 6, ["/bin/true", "__LWEND_aaaa__"]),
    ]
    fd, log = tempfile.mkstemp(suffix=".log")
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    fd, win = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps({"window_id": "w-1", "uuid": "aaaa", "kind": "attack",
                             "name": "T1059.004-1", "technique": "T1059.004",
                             "variant": None, "exit_code": 0, "ok": 1}) + "\n")
    fd, db = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return log, win, db


def test_window_scoping():
    log, win, db = _fixture()
    stats = normalize(log, win, "s-test", db)
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row

    w = conn.execute("SELECT * FROM windows").fetchone()
    assert w["ok"] == 1
    assert abs(w["ts_start"] - 100.05) < 1e-6
    assert abs(w["ts_end"] - 100.20) < 1e-6
    assert w["root_pid"] == 1000

    in_lab = {r["comm"]: r for r in conn.execute("SELECT * FROM events WHERE in_lab=1")}
    # activity and its grandchild are in; wrapper bash, sentinels and noise are out
    assert set(in_lab) == {"sh", "id"}
    assert in_lab["sh"]["window_id"] == "w-1"
    assert in_lab["sh"]["username"] == "admin"  # uid 1000 -> admin default map

    # parent enrichment: id's parent is the sh process
    assert in_lab["id"]["parent_comm"] == "sh"

    noise = conn.execute("SELECT in_lab FROM events WHERE comm='runc'").fetchone()
    assert noise["in_lab"] == 0
    assert stats["events_in_lab"] == 2


def test_missing_sentinel_marks_window_not_ok():
    log, win, db = _fixture()
    # Rewrite windows manifest to reference a uuid with no sentinels in the log.
    with open(win, "w") as fh:
        fh.write(json.dumps({"window_id": "w-x", "uuid": "zzzz", "kind": "attack",
                             "name": "X", "technique": "T1000", "variant": None,
                             "exit_code": 0, "ok": 1}) + "\n")
    normalize(log, win, "s-test2", db)
    conn = sqlite3.connect(db)
    w = conn.execute("SELECT ok FROM windows WHERE session_id='s-test2'").fetchone()
    assert w[0] == 0

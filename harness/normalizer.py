"""Turn raw auditd events into canonical rows in the events table.

Two jobs the parser does not do:

1. Categorize each event by the audit key we set in lab/audit.rules. This is
   arch independent and does not depend on syscall-number tables.

2. Scope events to lab windows by process tree. The sensor sees the whole VM, so
   Docker's own machinery is in the stream. A window's activity is exactly the
   process subtree rooted at the bash the executor spawned, bounded by the
   sentinel timestamps. The wrapper bash and the two sentinels are excluded, so
   what remains is the activity itself.
"""
import json
import sqlite3

from harness import schema
from harness.audit_parse import parse_log, decode_saddr

# audit key -> canonical category
KEY_CATEGORY = {
    "lab_exec": "process_creation",
    "lab_net": "network_connection",
    "lab_ptrace": "process_access",
    "lab_module": "module_load",
    "lab_cred": "file_event",
    "lab_persist": "file_event",
}

DEFAULT_UIDMAP = {0: "root", 1000: "admin", 65534: "nobody", 33: "www-data",
                  1: "daemon", 2: "bin", 999: "systemd-network"}


def _category(ev):
    key = ev.get("audit_key")
    if key in KEY_CATEGORY:
        return KEY_CATEGORY[key]
    # Fall back to syscall when the key is absent (should be rare).
    sc = ev.get("syscall")
    return {"execve": "process_creation", "execveat": "process_creation",
            "connect": "network_connection", "ptrace": "process_access",
            "init_module": "module_load", "finit_module": "module_load"}.get(sc, "other")


def _is_sentinel(ev):
    cl = ev.get("cmdline") or ""
    return "__LWSTART_" in cl or "__LWEND_" in cl


def _target_path(ev):
    """For a file_event, the path that matters is the watched file, not the loader."""
    for p in ev.get("paths", []):
        n = p.get("name") or ""
        if p.get("nametype") in ("NORMAL", "CREATE", "DELETE") and not n.endswith(".so.1"):
            return p.get("name"), p.get("nametype")
    return None, None


def _module_name(ev):
    for p in ev.get("paths", []):
        n = p.get("name") or ""
        if n.endswith(".ko") or n.endswith(".ko.xz"):
            return n
    return None


def normalize(audit_log, windows_jsonl, session_id, db_path, uid_map=None):
    uid_map = {**DEFAULT_UIDMAP, **(uid_map or {})}
    events = [e for e in parse_log(audit_log) if "syscall" in e]

    # Windows the executor recorded, keyed by uuid so we can find their sentinels.
    windows = []
    with open(windows_jsonl) as fh:
        for line in fh:
            line = line.strip()
            if line:
                windows.append(json.loads(line))

    # Resolve each window's real boundaries from the sentinel events themselves.
    starts, ends = {}, {}
    for e in events:
        cl = e.get("cmdline") or ""
        if "__LWSTART_" in cl:
            uid = cl.split("__LWSTART_")[1].split("__")[0]
            starts[uid] = e
        elif "__LWEND_" in cl:
            uid = cl.split("__LWEND_")[1].split("__")[0]
            ends[uid] = e

    resolved = []
    for w in windows:
        s, e = starts.get(w["uuid"]), ends.get(w["uuid"])
        if s is None or e is None:
            w = {**w, "ts_start": None, "ts_end": None, "root_pid": None, "ok": 0}
        else:
            w = {**w, "ts_start": s["ts"], "ts_end": e["ts"], "root_pid": s["ppid"],
                 "ok": w.get("ok", 1)}
        resolved.append(w)

    # Assign events to windows by process subtree within the time bound.
    for e in events:
        e["window_id"] = None
        e["in_lab"] = 0
    for w in resolved:
        if not w.get("ok") or w["ts_start"] is None:
            continue
        lo, hi, root = w["ts_start"], w["ts_end"], w["root_pid"]
        in_range = [e for e in events if lo <= e["ts"] <= hi]
        children = {}
        for e in in_range:
            children.setdefault(e.get("ppid"), []).append(e["pid"])
        # BFS the subtree rooted at the wrapper bash.
        subtree, stack, seen = set(), [root], {root}
        while stack:
            pid = stack.pop()
            for c in children.get(pid, []):
                if c not in seen:
                    seen.add(c)
                    subtree.add(c)
                    stack.append(c)
        for e in in_range:
            if e["pid"] in subtree and e["pid"] != root and not _is_sentinel(e):
                if e["window_id"] is None:  # first window wins; windows do not overlap
                    e["window_id"] = w["window_id"]
                    e["in_lab"] = 1

    _write(db_path, session_id, events, resolved, uid_map)
    return {
        "events_total": len(events),
        "events_in_lab": sum(e["in_lab"] for e in events),
        "windows_ok": sum(1 for w in resolved if w.get("ok")),
        "windows_total": len(resolved),
    }


def _write(db_path, session_id, events, windows, uid_map):
    conn = sqlite3.connect(db_path)
    schema.init_db(conn)
    conn.execute("DELETE FROM events WHERE session_id=?", (session_id,))
    conn.execute("DELETE FROM windows WHERE session_id=?", (session_id,))

    # Parent enrichment: most recent prior process_creation for a given pid.
    last_exec = {}
    for e in sorted(events, key=lambda x: x["ts"]):
        cat = _category(e)
        parent = last_exec.get(e.get("ppid"))
        dest_ip = dest_port = None
        if cat == "network_connection" and e.get("saddr"):
            dest_ip, dest_port = decode_saddr(e["saddr"])
        path, nametype = (None, None)
        if cat == "file_event":
            path, nametype = _target_path(e)
        row = {
            "ts": e["ts"], "audit_id": e["audit_id"], "category": cat,
            "syscall": e.get("syscall"), "pid": e.get("pid"), "ppid": e.get("ppid"),
            "comm": e.get("comm"), "exe": e.get("exe"), "cmdline": e.get("cmdline"),
            "cwd": e.get("cwd"), "tty": e.get("tty"),
            "uid": e.get("uid"), "gid": e.get("gid"), "euid": e.get("euid"),
            "auid": e.get("auid"), "username": uid_map.get(e.get("uid"), str(e.get("uid"))),
            "ses": e.get("ses"),
            "parent_exe": parent["exe"] if parent else None,
            "parent_cmdline": parent["cmdline"] if parent else None,
            "parent_comm": parent["comm"] if parent else None,
            "success": e.get("success"), "exit_code": e.get("exit_code"),
            "audit_key": e.get("audit_key"),
            "path": path, "path_nametype": nametype,
            "dest_ip": dest_ip, "dest_port": dest_port,
            "module_name": _module_name(e) if cat == "module_load" else None,
            "target_pid": None,
            "session_id": session_id, "window_id": e["window_id"], "in_lab": e["in_lab"],
            "raw": e["raw"],
        }
        cols = schema.EVENT_COLUMNS
        conn.execute(f"INSERT INTO events ({','.join(cols)}) VALUES ({','.join('?'*len(cols))})",
                     [row[c] for c in cols])
        if cat == "process_creation":
            last_exec[e["pid"]] = e

    for w in windows:
        row = {"window_id": w["window_id"], "session_id": session_id, "kind": w["kind"],
               "name": w["name"], "technique": w.get("technique"), "variant": w.get("variant"),
               "ts_start": w.get("ts_start") or 0.0, "ts_end": w.get("ts_end") or 0.0,
               "root_pid": w.get("root_pid"), "exit_code": w.get("exit_code"),
               "ok": w.get("ok", 0)}
        cols = schema.WINDOW_COLUMNS
        conn.execute(f"INSERT INTO windows ({','.join(cols)}) VALUES ({','.join('?'*len(cols))})",
                     [row[c] for c in cols])
    conn.commit()
    conn.close()

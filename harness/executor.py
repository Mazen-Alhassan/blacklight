"""Run atomics and benign activity inside the target, delimiting each with
sentinel processes so the normalizer can bound the window in the sensor's clock.

The executor never reads a clock to timestamp a window. It runs
    /bin/true __LWSTART_<uuid>__ ; <activity> ; /bin/true __LWEND_<uuid>__
and the sensor records those two execs like any other. The normalizer resolves
the window from the sentinel events. This removes clock skew between the
orchestrator, the target and the sensor from the measurement.
"""
import json
import subprocess
import uuid as uuidlib

TARGET = "lab-target"


def _exec_user(user, script):
    args = ["docker", "exec"]
    if user and user != "root":
        args += ["-u", user]
    args += [TARGET, "bash", "-c", script]
    return subprocess.run(args, capture_output=True, text=True, timeout=120)


def run_window(kind, name, command, user="admin", technique=None, variant=None):
    """Execute one activity as a delimited window. Returns the window manifest dict."""
    wid = f"w-{uuidlib.uuid4().hex[:10]}"
    marker = uuidlib.uuid4().hex[:12]
    wrapped = (f"/bin/true __LWSTART_{marker}__ ; "
               f"{{ {command} ; }} ; "
               f"/bin/true __LWEND_{marker}__")
    ok = 1
    exit_code = None
    try:
        r = _exec_user(user, wrapped)
        exit_code = r.returncode
    except subprocess.TimeoutExpired:
        ok = 0
        exit_code = -1
    return {
        "window_id": wid, "uuid": marker, "kind": kind, "name": name,
        "technique": technique, "variant": variant,
        "exit_code": exit_code, "ok": ok,
    }


def run_all(activities, windows_path):
    """activities: list of dicts with kind/name/command/user/technique/variant.
    Writes one manifest line per window to windows_path and returns them."""
    manifests = []
    with open(windows_path, "w") as fh:
        for a in activities:
            m = run_window(
                kind=a["kind"], name=a["name"], command=a["command"],
                user=a.get("user", "admin"), technique=a.get("technique"),
                variant=a.get("variant"),
            )
            fh.write(json.dumps(m) + "\n")
            fh.flush()
            manifests.append(m)
    return manifests

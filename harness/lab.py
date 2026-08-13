"""Lab lifecycle: bring the compose environment up, read the audit log the sensor
writes, and assert the kernel dropped nothing.

The audit log is bind mounted to data/audit/audit.log on the host, so we read it
directly. Rather than restart auditd per run, we record the file offset at session
start and snapshot only the bytes written since.
"""
import os
import re
import subprocess
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMPOSE = os.path.join(ROOT, "lab", "docker-compose.yml")
AUDIT_LOG = os.path.join(ROOT, "data", "audit", "audit.log")
SENSOR = "lab-sensor"
TARGET = "lab-target"


def _run(args, timeout=None, **kw):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, **kw)


def compose(*args, check=True, timeout=600):
    r = _run(["docker", "compose", "-f", COMPOSE, *args], timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"compose {' '.join(args)} failed:\n{r.stderr}")
    return r


def up(build=True, timeout=180):
    # `docker compose up -d` hangs on this Docker Desktop when the sensor uses
    # pid=host, but build + create + start is instant and does the same thing.
    os.makedirs(os.path.join(ROOT, "data", "audit"), exist_ok=True)
    # Start every session with a clean log by removing it before the sensor comes
    # up. Truncating a live auditd mid-session raced and dropped the first events,
    # so the reset happens here, while no auditd is attached to the file.
    if os.path.exists(AUDIT_LOG):
        os.remove(AUDIT_LOG)
    if build:
        compose("build", timeout=900)
    compose("create", timeout=120)
    compose("start", timeout=120)
    # Wait for the sensor to own the audit netlink AND for the exec rule to be
    # loaded. Waiting only for "enabled" raced: the first windows fired before
    # auditctl -R finished, so their execs were never audited and the windows
    # silently failed. The rule being present is the real readiness signal.
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = _run(["docker", "exec", SENSOR, "auditctl", "-s"])
        rules = _run(["docker", "exec", SENSOR, "auditctl", "-l"])
        ready = (s.returncode == 0 and "enabled" in s.stdout
                 and "lab_exec" in rules.stdout)
        if ready:
            t = _run(["docker", "exec", TARGET, "true"])
            if t.returncode == 0:
                return
        time.sleep(2)
    raise RuntimeError("lab did not become ready in time")


def down():
    compose("down", "-v", check=False)


def reset_log():
    """Start this session with an empty audit log.

    The log is a persisted host bind mount, so it carries content from previous
    runs. Truncating from inside the container (auditd opens the file O_APPEND, so
    the next write lands at offset 0) gives a clean per-session log without the
    host-side file-size races that Docker Desktop's FUSE mount introduces.
    """
    _run(["docker", "exec", SENSOR, "truncate", "-s", "0", "/var/log/audit/audit.log"],
         timeout=30)


def flush_and_read(out_path):
    """Flush auditd's buffer and read the whole log through the container.

    Reading via `docker exec cat` avoids the host bind-mount view entirely, which
    is the read that the FUSE lag was corrupting. Stopping auditd forces a
    complete flush before the read.
    """
    _run(["docker", "exec", SENSOR, "service", "auditd", "stop"], timeout=30)
    r = subprocess.run(["docker", "exec", SENSOR, "cat", "/var/log/audit/audit.log"],
                       capture_output=True, timeout=60)
    with open(out_path, "wb") as fh:
        fh.write(r.stdout)
    return len(r.stdout)


def audit_lost():
    r = _run(["docker", "exec", SENSOR, "auditctl", "-s"])
    m = re.search(r"^lost (\d+)", r.stdout, re.MULTILINE)
    return int(m.group(1)) if m else -1


def uid_map():
    """Read the target's /etc/passwd so uid resolution matches the lab image."""
    r = _run(["docker", "exec", TARGET, "cat", "/etc/passwd"])
    out = {}
    for line in r.stdout.splitlines():
        parts = line.split(":")
        if len(parts) >= 3 and parts[2].isdigit():
            out[int(parts[2])] = parts[0]
    return out

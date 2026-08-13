#!/bin/bash
# Sensor entrypoint. Starts auditd, loads the lab rule set, then idles.
# The raw audit.log is written to /var/log/audit which the compose file bind
# mounts to the host so the orchestrator can read it without docker cp.
set -e

# auditd insists on an empty log dir owned correctly.
mkdir -p /var/log/audit

# Start the daemon. It attaches to the kernel audit netlink.
service auditd start

# Give it a moment to own the netlink before we push rules.
sleep 1

# Load rules. auditctl -R exits non-zero on the "remove_rule" churn but the
# rules do load, so we tolerate it and verify below.
auditctl -R /etc/audit/lab.rules || true

echo "[sensor] audit status:"
auditctl -s | grep -E "enabled|backlog_limit|lost" || true
echo "[sensor] loaded rules:"
auditctl -l | head -20
echo "[sensor] ready"

# Idle forever. The orchestrator drives everything else via docker exec.
exec tail -f /dev/null

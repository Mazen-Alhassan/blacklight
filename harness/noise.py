"""Benign corpus generator. Produces windows of ordinary activity so every rule
gets a measured false positive rate.

The generator returns activity dicts the executor runs like any other window,
tagged kind=benign. Commands are sampled and lightly parameterized so windows
vary the way a real machine varies, without being so expensive that a couple
hundred of them take an hour. A weak benign corpus gives a fake 0% FP rate, so
the profiles below deliberately overlap the vocabulary attackers use: they run
tar, chmod, find, curl, base64 and shells, because those are also ordinary.
"""
import random

PROFILES = [
    {
        "name": "admin_recon", "user": "admin",
        "commands": [
            "ls -la /var/log", "df -h", "free -m", "ps aux | head -20",
            "cat /etc/hostname", "uptime", "id && whoami", "w 2>/dev/null || true",
            "du -sh /var/log 2>/dev/null", "ss -tlnp 2>/dev/null | head",
            "top -bn1 | head -15", "cat /proc/loadavg", "uname -r",
        ],
    },
    {
        "name": "package_mgmt", "user": "root",
        "commands": [
            "dpkg -l | wc -l", "dpkg --status coreutils >/dev/null",
            "apt-cache policy bash 2>/dev/null | head", "ldconfig -p | head",
            "dpkg -L coreutils >/dev/null", "which gcc python3 curl",
            "apt-mark showmanual 2>/dev/null | head",
        ],
    },
    {
        "name": "ci_build", "user": "admin",
        "commands": [
            "printf 'int main(){return 0;}' > /tmp/a.c && gcc /tmp/a.c -o /tmp/a && /tmp/a",
            "python3 -c 'print(sum(range(1000)))'",
            "tar -czf /tmp/src.tgz /etc/hostname 2>/dev/null && tar -tzf /tmp/src.tgz >/dev/null",
            "make --version >/dev/null && echo built",
            "python3 -m py_compile /etc/os-release 2>/dev/null; echo ok",
            "gcc --version | head -1",
            "find /usr/include -name '*.h' 2>/dev/null | head -5 >/dev/null",
        ],
    },
    {
        "name": "backup_job", "user": "root",
        "commands": [
            "rsync -a /etc/hostname /tmp/bk_hostname 2>/dev/null; echo synced",
            "tar -cf /tmp/etc.tar /etc/hostname /etc/os-release 2>/dev/null && echo archived",
            "gzip -kf /tmp/etc.tar 2>/dev/null; echo compressed",
            "find /var/log -type f -mtime -1 2>/dev/null | head >/dev/null",
            "cp -a /etc/os-release /tmp/os.bak && echo copied",
        ],
    },
    {
        "name": "log_rotate", "user": "root",
        "commands": [
            "cp /var/log/dpkg.log /tmp/dpkg.log.1 2>/dev/null; echo rotated",
            "gzip -f /tmp/dpkg.log.1 2>/dev/null; echo compressed",
            "find /tmp -name '*.1' -delete 2>/dev/null; echo cleaned",
            "truncate -s 0 /tmp/scratch.log 2>/dev/null; echo truncated",
        ],
    },
    {
        "name": "user_admin", "user": "root",
        "commands": [
            "getent passwd root >/dev/null && echo ok",
            "id admin", "groups admin 2>/dev/null || true",
            "chage -l admin 2>/dev/null | head -2 || true",
            "cat /etc/group | wc -l",
        ],
    },
    {
        "name": "web_health", "user": "admin",
        "commands": [
            "curl --max-time 2 -s http://127.0.0.1/ >/dev/null 2>&1 || true",
            "curl --max-time 2 -sI http://127.0.0.1:8080/health >/dev/null 2>&1 || true",
            "wget -q -T 2 -O /dev/null http://127.0.0.1/ 2>/dev/null || true",
            "getent hosts localhost >/dev/null || true",
        ],
    },
    {
        "name": "config_edit", "user": "admin",
        "commands": [
            "cp /etc/os-release /tmp/os.conf && echo edited",
            "grep -c '.' /etc/os-release",
            "chmod 644 /tmp/os.conf && echo chmodded",
            "diff /etc/os-release /tmp/os.conf >/dev/null 2>&1; echo compared",
            "sha256sum /etc/os-release >/dev/null && echo hashed",
        ],
    },
    {
        "name": "cron_maintenance", "user": "root",
        "commands": [
            "crontab -l 2>/dev/null | head || echo no-crontab",
            "ls -la /etc/cron.d 2>/dev/null >/dev/null; echo listed",
            "systemctl list-timers 2>/dev/null | head -3 || true",
        ],
    },
    {
        "name": "dev_shell", "user": "admin",
        "commands": [
            "sh -c 'echo building; ls /tmp >/dev/null'",
            "bash -c 'for i in 1 2 3; do echo $i >/dev/null; done'",
            "sh -c 'date +%s >/dev/null'",
            "python3 -c 'import os; os.listdir(\"/tmp\")'",
            "base64 /etc/hostname >/dev/null && echo encoded",
        ],
    },
]


def generate_benign(count, seed=1337):
    rng = random.Random(seed)
    out = []
    for i in range(count):
        prof = PROFILES[i % len(PROFILES)]
        cmd = rng.choice(prof["commands"])
        out.append({
            "kind": "benign", "name": prof["name"], "command": cmd,
            "user": prof["user"], "technique": None, "variant": None,
        })
    return out

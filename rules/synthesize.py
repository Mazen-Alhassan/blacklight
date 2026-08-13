"""rule-synth: turn threat-intel notes into candidate Sigma rules.

This stands in for the LLM rule-synthesis agent. Each entry below is a candidate
derived from a real technique writeup (see intel/), carrying an explicit
hypothesis about which telemetry field holds the signal. The harness then tests
that hypothesis. When a hypothesis is wrong (a Sysmon field the Linux lab does
not carry, a file-open the containerized sensor cannot see), the rule is reported
broken or unfirable instead of silently never firing. That gap is the finding.

Run: python -m rules.synthesize   (writes rules/candidate/*.yml)
"""
import os
import textwrap
import uuid

import yaml

NS = uuid.UUID("7b1d0c2a-0000-0000-0000-000000000000")

OUT = os.path.join(os.path.dirname(__file__), "candidate")

# Each rule: (filename, hypothesis-comment, rule-dict). The hypothesis is what the
# author expected the lab to carry. The harness decides whether it was right.
RULES = [
    # ---- expected to validate: signal is in process argv, which auditd carries ----
    ("sysinfo_discovery",
     "Signal is the argv of uname/hostnamectl. auditd EXECVE carries full argv.",
     dict(title="System information discovery via uname",
          tags=["attack.discovery", "attack.t1082"], level="low",
          category="process_creation",
          detection={"sel": {"cmdline|contains": ["uname -a", "uname -r", "hostnamectl",
                                                    "/etc/os-release"]},
                     "condition": "sel"})),
    ("local_account_discovery",
     "Reading /etc/passwd with cat/getent shows up in argv.",
     dict(title="Local account discovery via passwd read",
          tags=["attack.discovery", "attack.t1087.001"], level="low",
          category="process_creation",
          detection={"sel": {"exe|endswith": ["/cat", "/getent"],
                              "cmdline|contains": "/etc/passwd"},
                     "condition": "sel"})),
    ("ingress_tool_transfer_curl",
     "A downloader writing to a file: curl/wget with an output flag and an http URL.",
     dict(title="Ingress tool transfer via curl or wget",
          tags=["attack.command_and_control", "attack.t1105"], level="medium",
          category="process_creation",
          detection={"sel": {"exe|endswith": ["/curl", "/wget"],
                              "cmdline|contains": "http"},
                     "save": {"cmdline|contains": [" -o", " -O", "--output"]},
                     "condition": "sel and save"})),
    ("external_http_beacon",
     "Beaconing curl to a non-local host. Filter localhost to keep health checks out.",
     dict(title="HTTP request to external host",
          tags=["attack.command_and_control", "attack.t1071.001"], level="medium",
          category="process_creation",
          detection={"sel": {"exe|endswith": ["/curl", "/wget"],
                              "cmdline|contains": "http"},
                     "localhost": {"cmdline|contains": ["127.0.0.1", "localhost", "0.0.0.0"]},
                     "condition": "sel and not localhost"})),
    ("clear_command_history",
     "History wipe leaves the file path and the clearing verb in argv.",
     dict(title="Shell history cleared",
          tags=["attack.defense_evasion", "attack.t1070.003"], level="medium",
          category="process_creation",
          detection={"sel": {"cmdline|contains": [".bash_history", "history -c",
                                                    "HISTFILE=/dev/null"]},
                     "condition": "sel"})),
    ("permissive_chmod",
     "World-writable or setuid chmod on a dropped file.",
     dict(title="Overly permissive file mode set",
          tags=["attack.defense_evasion", "attack.t1222.002"], level="medium",
          category="process_creation",
          detection={"sel": {"exe|endswith": "/chmod",
                              "cmdline|contains": ["777", "u+s", "4755", "+s"]},
                     "condition": "sel"})),
    ("sudo_privilege_enum",
     "sudo -l to enumerate what the account can run.",
     dict(title="Sudo privilege enumeration",
          tags=["attack.privilege_escalation", "attack.t1548.003"], level="low",
          category="process_creation",
          detection={"sel": {"exe|endswith": "/sudo", "cmdline|contains": " -l"},
                     "condition": "sel"})),
    ("credentials_in_files",
     "Grepping the tree for passwords or secrets.",
     dict(title="Credential search across files",
          tags=["attack.credential_access", "attack.t1552.001"], level="medium",
          category="process_creation",
          detection={"sel": {"exe|endswith": "/grep",
                              "cmdline|contains": ["password", "secret", "id_rsa", "BEGIN "]},
                     "condition": "sel"})),
    ("ptrace_process_injection",
     "ptrace attach is a syscall auditd records directly, no argv needed.",
     dict(title="Process injection via ptrace",
          tags=["attack.defense_evasion", "attack.t1055.008"], level="high",
          category="process_access",
          detection={"sel": {"syscall": "ptrace"}, "condition": "sel"})),
    ("base64_decode_pipe_shell",
     "Decode-and-run: base64 -d piped to a shell.",
     dict(title="Base64 payload decoded and executed",
          tags=["attack.defense_evasion", "attack.t1140"], level="medium",
          category="process_creation",
          detection={"sel": {"cmdline|contains": ["base64 -d", "base64 --decode",
                                                    "base64 -D"]},
                     "condition": "sel"})),
    ("disable_security_tools",
     "Stopping logging or the firewall from the command line.",
     dict(title="Security tooling disabled",
          tags=["attack.defense_evasion", "attack.t1562.001"], level="high",
          category="process_creation",
          detection={"sel": {"cmdline|contains": ["systemctl stop rsyslog",
                                                    "systemctl stop auditd", "setenforce 0",
                                                    "ufw disable", "service auditd stop"]},
                     "condition": "sel"})),
    ("kernel_module_load_exec",
     "Loading a module via insmod/modprobe. Note: both are symlinks to kmod, so the "
     "binary path is /bin/kmod; the tool name only survives in argv[0]. Match cmdline.",
     dict(title="Kernel module load via insmod or modprobe",
          tags=["attack.persistence", "attack.t1547.006"], level="high",
          category="process_creation",
          detection={"sel": {"cmdline|startswith": ["insmod", "modprobe", "/sbin/insmod",
                                                      "/sbin/modprobe"]},
                     "condition": "sel"})),

    # ---- expected to be noisy: the vocabulary overlaps ordinary admin work ----
    ("process_discovery_ps",
     "ps aux for process discovery. Admins run this too, so watch the FP rate.",
     dict(title="Process discovery via ps",
          tags=["attack.discovery", "attack.t1057"], level="low",
          category="process_creation",
          detection={"sel": {"exe|endswith": "/ps", "cmdline|contains": ["aux", "-ef"]},
                     "condition": "sel"})),
    ("file_discovery_find",
     "find sweeping the filesystem. Overlaps backup and build jobs.",
     dict(title="File and directory discovery via find",
          tags=["attack.discovery", "attack.t1083"], level="low",
          category="process_creation",
          detection={"sel": {"exe|endswith": "/find"}, "condition": "sel"})),
    ("archive_for_exfil_tar",
     "tar czf to stage data. Also exactly what backups do.",
     dict(title="Data staged into an archive",
          tags=["attack.collection", "attack.t1560.001"], level="medium",
          category="process_creation",
          detection={"sel": {"exe|endswith": "/tar",
                              "cmdline|contains": ["czf", "-czf", "cvf", "-c "]},
                     "condition": "sel"})),
    ("cron_persistence",
     "Touching cron paths. Listing them is benign, so expect false positives.",
     dict(title="Cron persistence activity",
          tags=["attack.persistence", "attack.t1053.003"], level="medium",
          category="process_creation",
          detection={"sel": {"cmdline|contains": ["/etc/cron.d", "crontab", "/var/spool/cron"]},
                     "condition": "sel"})),

    # ---- expected partial: covers the inline form, misses the piped form ----
    ("unix_shell_recon_oneliner_v2",
     "sh -c with a recon chain. Note: will not see recon piped in via stdin.",
     dict(title="Unix shell reconnaissance one-liner",
          tags=["attack.execution", "attack.t1059.004"], level="medium",
          category="process_creation",
          detection={"shell": {"exe|endswith": ["/sh", "/bash", "/dash"],
                               "cmdline|contains": "-c"},
                     "recon": {"cmdline|contains": ["id", "whoami", "uname"]},
                     "condition": "shell and recon"})),

    # ---- expected broken: Windows/Sysmon fields the Linux lab does not carry ----
    ("win_lsass_memory_access",
     "HYPOTHESIS WRONG ON THIS LAB: assumes Sysmon EventID 10 GrantedAccess. Not present.",
     dict(title="LSASS memory access (Sysmon)",
          tags=["attack.credential_access", "attack.t1003.001"], level="high",
          product="windows", service="sysmon", category="process_access",
          detection={"sel": {"TargetImage|endswith": "\\lsass.exe",
                             "GrantedAccess": "0x1010"}, "condition": "sel"})),
    ("win_rundll32_unsigned",
     "HYPOTHESIS WRONG: assumes Sysmon Hashes and IntegrityLevel. Linux auditd has neither.",
     dict(title="Suspicious rundll32 execution (Sysmon)",
          tags=["attack.defense_evasion", "attack.t1218.011"], level="high",
          product="windows", service="sysmon", category="process_creation",
          detection={"sel": {"Image|endswith": "\\rundll32.exe",
                             "Hashes|contains": "MD5=", "IntegrityLevel": "System"},
                     "condition": "sel"})),
    ("win_scheduled_task_persistence",
     "HYPOTHESIS WRONG: assumes Windows EventID 4698 and TaskName. Field missing.",
     dict(title="Scheduled task created (Windows)",
          tags=["attack.persistence", "attack.t1053.005"], level="medium",
          product="windows", service="security",
          detection={"sel": {"EventID": 4698, "TaskName|contains": "\\"},
                     "condition": "sel"})),
    ("win_registry_run_key",
     "HYPOTHESIS WRONG: assumes Sysmon EventID 13 registry TargetObject. No registry on Linux.",
     dict(title="Registry run key persistence (Sysmon)",
          tags=["attack.persistence", "attack.t1547.001"], level="medium",
          product="windows", service="sysmon", category="registry_set",
          detection={"sel": {"TargetObject|contains": "\\CurrentVersion\\Run",
                             "Details|contains": ".exe"}, "condition": "sel"})),

    # ---- expected unfirable: field is mapped and real, but never populated here ----
    ("shadow_file_read",
     "HYPOTHESIS UNTESTED UNTIL RUN: assumes a file-open event for /etc/shadow. The "
     "containerized sensor's path watch is inode/namespace bound, so target opens are unseen.",
     dict(title="Shadow file accessed",
          tags=["attack.credential_access", "attack.t1003.008"], level="high",
          category="file_event",
          detection={"sel": {"TargetFilename|endswith": "/etc/shadow"}, "condition": "sel"})),
    ("driver_load_module",
     "HYPOTHESIS: assumes a module_load (finit_module) event. Only fires on a real load, "
     "which does not happen in the container, so this stays unfirable.",
     dict(title="Kernel driver loaded",
          tags=["attack.persistence", "attack.t1547.006"], level="high",
          category="driver_load",
          detection={"sel": {"ImageLoaded|endswith": ".ko"}, "condition": "sel"})),
    ("shell_spawned_by_sshd",
     "HYPOTHESIS: assumes ParentImage is sshd. In this lab the parent is always the "
     "harness shell, so the field is present but never that value.",
     dict(title="Shell spawned by sshd",
          tags=["attack.execution", "attack.t1059.004"], level="medium",
          category="process_creation",
          detection={"sel": {"ParentImage|endswith": "/sshd",
                             "exe|endswith": ["/sh", "/bash"]}, "condition": "sel"})),
]


def build(entry):
    fname, hypothesis, r = entry
    ls = {}
    if r.get("product"):
        ls["product"] = r["product"]
    else:
        ls["product"] = "linux"
    if r.get("category"):
        ls["category"] = r["category"]
    if r.get("service"):
        ls["service"] = r["service"]
    doc = {
        "title": r["title"],
        "id": str(uuid.uuid5(NS, fname)),
        "status": "experimental",
        "description": r["title"],
        "author": "rule-synth",
        "date": "2026/08/12",
        "tags": r["tags"],
        "logsource": ls,
        "detection": r["detection"],
        "level": r["level"],
    }
    text = "# field hypothesis: " + "\n#   ".join(
        textwrap.wrap(hypothesis, 88)) + "\n"
    text += yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)
    return fname, text


def main():
    os.makedirs(OUT, exist_ok=True)
    # Clear previously generated candidates but keep the phase-1 hand-written rule.
    for entry in RULES:
        fname, text = build(entry)
        with open(os.path.join(OUT, f"{fname}.yml"), "w") as fh:
            fh.write(text)
    print(f"wrote {len(RULES)} candidate rules to {OUT}")


if __name__ == "__main__":
    main()

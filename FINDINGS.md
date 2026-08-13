# Findings

One run, 24 candidate rules, session `s-622b08`, committed as `data/results.json`. The lab observed 2509 audit events, 676 of them attributable to lab activity across 42 attack windows, 3 evasion windows, and 150 benign windows. The kernel dropped zero events.

## 1. What the run found

| Status | Count | Meaning |
|---|---|---|
| validated | 9 | fired on every attack window for its technique, FP rate at or under 1% |
| noisy | 6 | fired on the attack, but FP rate over 1% |
| partial | 1 | fired on some attack windows, not all |
| unfirable | 4 | every field present, but it never fired |
| broken | 4 | references a field the lab does not carry |

So 16 of 24 rules produced a true positive on their own technique, and 9 of those are clean enough to ship. The median false positive rate across the 16 firing rules is 0%, because most of the clean rules never touched a benign window. The noisy tail is what makes the median uninteresting and the distribution interesting: it runs from 1.33% up to 17.33%.

Median detection latency across firing rules is about 1 ms, measured from the first event in the attack window to the first event the rule matched. The outlier is `ptrace_process_injection` at 32.5 ms, which is real: the ptrace attach happens a beat after the python interpreter that performs it starts, so the rule sits slightly deeper into the technique than the argv-matching rules do.

## 2. The validated set

Nine rules fired on every attack window for their technique with a false positive rate at or under 1%:

```
base64_decode_pipe_shell     T1140      2/2   0.00%
clear_command_history        T1070.003  2/2   0.00%
credentials_in_files         T1552.001  2/2   0.00%
external_http_beacon         T1071.001  2/2   0.00%
kernel_module_load_exec      T1547.006  2/2   0.00%
local_account_discovery      T1087.001  2/2   0.00%
permissive_chmod             T1222.002  2/2   0.00%
ptrace_process_injection     T1055.008  2/2   0.00%
sudo_privilege_enum          T1548.003  2/2   0.00%
```

`external_http_beacon` is worth calling out. It fires on a curl to a non-local host and filters localhost, so the benign `web_health` profile that curls `127.0.0.1` all day does not trip it, while the beacon to `192.0.2.1` does. That filter is the difference between this rule and `ingress_tool_transfer_curl`, which is noisy.

## 3. Why the failures failed, by category

The interesting half of the project is the 8 rules that never fired on their technique. They fail for four distinct reasons, and the harness tells them apart.

**Wrong field, Windows telemetry on a Linux box (4 rules, `broken`).** Every broken rule is a Sigma rule written for Sysmon or the Windows Security log, and the harness names the exact missing field:

```
win_lsass_memory_access         GrantedAccess
win_rundll32_unsigned           Hashes, IntegrityLevel
win_scheduled_task_persistence  EventID, TaskName
win_registry_run_key            Details, TargetObject
```

`win_scheduled_task_persistence` is the row worth showing a reviewer. It is a perfectly reasonable rule that assumes Windows Event ID 4698. On this lab that field does not exist, so the rule cannot fire, and without the harness it would sit in the repo looking like coverage. This is the exact failure mode the project was built to catch.

**Field present, never populated (1 rule, `unfirable`).** `shell_spawned_by_sshd` keys on `ParentImage` ending in `/sshd`. The field is mapped and populated in this lab, it just never holds `sshd`, because the parent of everything the harness runs is the harness shell. The rule is not broken. It is aimed at a parent this lab never produces.

**Technique not observable in this telemetry (2 rules, `unfirable`).** `shadow_file_read` wants a file-open event for `/etc/shadow`. auditd `-w` watches are inode and namespace bound, so the sensor never sees a file open inside the target container. `driver_load_module` wants a `finit_module` event, which only fires on a real kernel module load, and nothing in the container loads one. Both are honest gaps in what a single containerized auditd can see.

**Tool not present, so the technique cannot execute (1 rule, `unfirable`).** `disable_security_tools` matches `systemctl stop`, `setenforce`, and `ufw disable`. The container has no systemd, no SELinux, and no ufw, so those binaries never exec and there is nothing to match. The rule is fine. The lab cannot host the technique.

## 4. What the adversary found

The evasion pass runs a variant of each atomic that still performs the technique but tries to slip the rule. Three variants ran against the firing rules. Two got through.

```
rule                          variant           result
unix_shell_recon_oneliner_v2  renamed_binary    EVADED
unix_shell_recon_oneliner_v2  env_indirection   caught
ingress_tool_transfer_curl    renamed_curl      EVADED
```

Both evasions work the same way, and it is the same weakness. Both rules anchor on `exe` ending in a known binary path (`/sh`, `/curl`). Copy the binary to a new name first (`cp /bin/sh /tmp/notashell; /tmp/notashell -c ...`, or `cp /usr/bin/curl /tmp/dl; /tmp/dl ...`) and the `exe` no longer matches, so the rule goes quiet while the technique runs. The `env_indirection` variant, which hides the recon commands behind shell variables but still runs through `sh -c`, gets caught, because that rule also checks the command line and the shell invocation is still visible.

The lesson is specific: any rule whose only selective clause is `Image|endswith` a well-known interpreter is one `cp` away from blind. A command-line clause survives a rename. This is why `unix_shell_recon_oneliner_v2` is only `partial` in the first place, and it is the row that shows detection is adversarial rather than a checklist.

## 5. On the rule synthesizer

The 24 candidates were generated from an intel table by `rules/synthesize.py`, each carrying a written hypothesis about which field would hold the signal. A third of them (8 of 24) turned out to be unfirable or broken against this telemetry. That ratio is itself the finding: writing a plausible Sigma rule is easy, and a third of plausible rules do not fire in a given environment for reasons you cannot see by reading them. The value is in testing the hypothesis, not in writing more rules.

## 6. What I would tell a team acting on this

Ship the nine validated rules and keep watching their false positive rate, because a synthetic benign corpus flatters them. Do not ship the six noisy rules as alerts; route them to a lower-priority feed or add a filter clause the way `external_http_beacon` filters localhost, since `sysinfo_discovery` at 17.33% will be muted by the SOC within a week otherwise. Treat the four broken rules as a coverage gap to close with a Windows sensor, not as coverage you have. And rewrite the two evaded rules to anchor on the command line rather than the binary path, because the rename that beat them takes an attacker one command.

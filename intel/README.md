# Threat intel notes

These are the source notes the candidate rules in `rules/candidate/` were written
from. Each names the technique, the observable it assumes, and the log field the
author bet the signal would land in. The harness then tests that bet. Where the
bet was wrong (a Windows Sysmon field on a Linux box, a file-open the sensor
cannot see across a container boundary) the rule is reported broken or unfirable
rather than quietly never firing.

The point of writing the field hypothesis down first is that a wrong hypothesis
becomes a clean signal instead of a mystery.

## Sources

The techniques below are standard, well documented tradecraft. Primary references:

- MITRE ATT&CK for the technique definitions (`https://attack.mitre.org`).
- CISA advisories on Linux post-exploitation, e.g. the joint guidance on detecting
  living-off-the-land activity (`https://www.cisa.gov/known-exploited-vulnerabilities-catalog`).
- Atomic Red Team for the executable test format the atomics follow
  (`https://github.com/redcanaryco/atomic-red-team`).

## Technique notes

| Technique | Observable | Field hypothesis | Outcome expected |
|---|---|---|---|
| T1059.004 Unix shell | `sh -c` with a recon chain | argv in `cmdline` | fires on inline, misses stdin-piped |
| T1082 System info | uname / hostnamectl | `cmdline` | fires, but overlaps admin work |
| T1087.001 Account discovery | cat /etc/passwd | `exe` + `cmdline` | fires |
| T1057 Process discovery | ps aux | `exe` + `cmdline` | fires, noisy |
| T1083 File discovery | find | `exe` | fires, noisy |
| T1105 Ingress transfer | curl/wget with output flag | `exe` + `cmdline` | fires |
| T1071.001 Web C2 | curl to non-local host | `cmdline` + filter | fires |
| T1070.003 Clear history | rm ~/.bash_history | `cmdline` | fires |
| T1222.002 File perms | chmod 777 / u+s | `exe` + `cmdline` | fires |
| T1548.003 Sudo | sudo -l | `exe` + `cmdline` | fires |
| T1552.001 Creds in files | grep -r password | `exe` + `cmdline` | fires |
| T1055.008 Ptrace | ptrace syscall | `syscall` (process_access) | fires |
| T1560.001 Archive | tar czf | `exe` + `cmdline` | fires, noisy |
| T1547.006 Kernel module | insmod/modprobe | `cmdline` (argv, not exe: both are kmod symlinks) | fires |
| T1053.003 Cron | write /etc/cron.d | `cmdline` | fires, noisy |
| T1562.001 Disable tools | systemctl stop / setenforce | `cmdline` | fires |
| T1140 Deobfuscate | base64 -d \| sh | `cmdline` | fires |
| T1003.008 Shadow read | open /etc/shadow | `TargetFilename` (file_event) | UNFIRABLE: watch is namespace-bound |
| T1003.001 LSASS | Sysmon EventID 10 | `GrantedAccess` | BROKEN: Windows field |
| T1218.011 Rundll32 | Sysmon process create | `Hashes`, `IntegrityLevel` | BROKEN: Windows field |
| T1053.005 Scheduled task | Windows EventID 4698 | `EventID`, `TaskName` | BROKEN: Windows field |
| T1547.001 Run key | Sysmon EventID 13 | `TargetObject` | BROKEN: no registry on Linux |

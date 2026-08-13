# ARCHITECTURE

Derived from `docs/SPEC.md`. The schemas in this document are the contract. Everything downstream reads them, so they are fixed before implementation starts.

## Shape of the thing

```
intel/*.md ──▶ rule authoring ──▶ rules/candidate/*.yml
                                          │
   ┌──────────────────────────────────────┼───────────────────────────────┐
   │                 VALIDATION HARNESS    │                              │
   │                                       ▼                              │
   │  lab up ──▶ executor ──▶ sensor ──▶ normalizer ──▶ telemetry.db      │
   │   (compose)  atomics +   (auditd)   (auditd ──▶     (SQLite)         │
   │              benign                  canonical)        │             │
   │              profiles                                  ▼             │
   │                                                   engine (pySigma)   │
   │                                                        │             │
   │                                                        ▼             │
   │                                                     scoring          │
   └────────────────────────────────────────────────────────┼─────────────┘
                                                            ▼
                                                    data/results.json
                                                            │
                                              report/render.py ──▶ report.html
                                              report/shoot.py  ──▶ hero.png
```

## Why this sensor

The lab runs Linux with **auditd** as the only sensor. That is a deliberate narrowing from the original sketch, which also named Falco.

auditd covers the whole surface this project needs from one sensor: process execution (`execve`, `execveat`), file access (watches), network connect (`connect`, `socket`), credential access (watches on `/etc/shadow`), kernel module load (`init_module`, `finit_module`) and `ptrace`. Adding a second sensor would double the normalizer, double the field mapping table, and split the field-availability analysis across two vocabularies. The interesting result in this project is what a real rule set does against one honestly described telemetry source, not how many agents are installed.

The cost of that choice is written down in the limitations, and it is real: auditd carries no process hashes, no signature information and no native parent process name.

### Verified before committing to it

The Docker Desktop LinuxKit kernel (6.10.14, arm64) was probed directly:

- `CONFIG_AUDIT=y`, `CONFIG_AUDITSYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`
- A privileged sensor container with `--pid=host` observes `execve` in a *separate, unprivileged* container. Confirmed with 200 tagged execs from a second container, all recorded.
- The kernel default `backlog_limit` is 64, which drops events under any real load. The lab raises it to 16384. At that setting a 200-exec burst produced `lost 0`, `backlog 14`.

That last point is the kind of thing that silently ruins a measurement, so the harness asserts `lost == 0` after every run and fails the run if the kernel dropped events.

## Modules

| Module | Responsibility | Must not |
|---|---|---|
| `lab/` | Compose file, sensor image, target image, audit rule set | Contain any scoring logic |
| `harness/sensor.py` | Start/stop the sensor, drain `audit.log`, assert no loss | Interpret events |
| `harness/executor.py` | Run one atomic or benign profile in the target, emit sentinels | Know about Sigma |
| `harness/normalizer.py` | auditd records to canonical events, write SQLite | Invent fields |
| `harness/noise.py` | Generate the benign corpus | Know about rules |
| `engine/` | Sigma to SQL via pySigma, field availability analysis | Score anything |
| `scoring/` | Windows plus matches to `results.json` | Query the sensor |
| `report/` | `results.json` to HTML and PNG | Read the database |

The one-way dependency rule: `report` reads only `results.json`, `scoring` reads only the database and the engine's match output, `engine` reads only rules and the database schema. Nothing reads back up the chain.

## Schema 1: canonical telemetry event

SQLite table `events`. One row per observed kernel event. This is the vocabulary Sigma rules are mapped onto.

```sql
CREATE TABLE events (
  id            INTEGER PRIMARY KEY,
  ts            REAL    NOT NULL,   -- epoch seconds, sensor clock, from the audit record
  audit_id      INTEGER NOT NULL,   -- audit event serial, groups multi-record events
  category      TEXT    NOT NULL,   -- process_creation | file_event | network_connection
                                    -- | process_access | module_load
  syscall       TEXT,
  -- process identity
  pid           INTEGER,
  ppid          INTEGER,
  comm          TEXT,               -- kernel comm, truncated to 15 chars by the kernel
  exe           TEXT,               -- full path of the executable
  cmdline       TEXT,               -- reconstructed from EXECVE a0..aN
  cwd           TEXT,
  tty           TEXT,
  -- identity
  uid           INTEGER,
  gid           INTEGER,
  euid          INTEGER,
  auid          INTEGER,            -- login uid, -1/4294967295 when unset
  username      TEXT,               -- resolved from uid inside the target image
  ses           TEXT,
  -- derived, nullable, see note below
  parent_exe    TEXT,
  parent_cmdline TEXT,
  parent_comm   TEXT,
  -- outcome
  success       INTEGER,
  exit_code     INTEGER,
  audit_key     TEXT,
  -- category specific
  path          TEXT,               -- file_event: target path
  path_nametype TEXT,
  dest_ip       TEXT,               -- network_connection
  dest_port     INTEGER,
  module_name   TEXT,               -- module_load
  target_pid    INTEGER,            -- process_access: ptrace target
  -- lab bookkeeping
  session_id    TEXT NOT NULL,
  window_id     TEXT,               -- NULL for events outside any window
  in_lab        INTEGER NOT NULL,   -- 1 if descended from the lab session root
  raw           TEXT NOT NULL       -- original audit record text, kept for FINDINGS
);
```

**On the derived parent fields.** auditd gives `ppid` and nothing else about the parent. `parent_exe`, `parent_cmdline` and `parent_comm` are reconstructed by looking up the most recent prior `process_creation` event for that pid within the session. This is genuine enrichment and it is lossy in one specific way: if the parent process execed before the sensor started, or never execed at all, the parent fields are NULL. The normalizer records that as NULL rather than guessing. Rules that depend on `ParentImage` therefore inherit a real coverage hole, and the report has to show it.

**On scoping.** `in_lab` is computed by walking the `ppid` chain up to the known session root pid. The sensor sees the entire VM, including Docker's own machinery, so this is how lab activity is separated from infrastructure noise. It is exact, unlike PID-to-container-ID mapping, which races against process exit.

## Schema 2: windows

```sql
CREATE TABLE windows (
  window_id   TEXT PRIMARY KEY,
  session_id  TEXT NOT NULL,
  kind        TEXT NOT NULL,   -- attack | benign | evasion
  name        TEXT NOT NULL,   -- atomic id or benign profile name
  technique   TEXT,            -- e.g. T1059.004, NULL for benign
  variant     TEXT,            -- evasion variant name, NULL otherwise
  ts_start    REAL NOT NULL,   -- sentinel start event timestamp
  ts_end      REAL NOT NULL,   -- sentinel end event timestamp
  exit_code   INTEGER,
  ok          INTEGER NOT NULL -- 0 if the activity itself failed to run
);
```

A window with `ok = 0` is excluded from scoring entirely. An atomic that failed to execute proves nothing about a rule either way, and counting it as a miss would be a lie.

## Schema 3: `data/results.json`

The contract. Locked.

```json
{
  "generated_at": "2026-08-12T14:00:00Z",
  "lab": {
    "sensor": "auditd",
    "kernel": "6.10.14-linuxkit",
    "arch": "aarch64",
    "target_image": "lab-target:1",
    "audit_lost": 0
  },
  "run": {
    "session_id": "s-8f21",
    "events_total": 41822,
    "events_in_lab": 12904,
    "attack_windows": 62,
    "benign_windows": 400,
    "evasion_windows": 24,
    "noise_threshold": 0.01
  },
  "rules": [
    {
      "id": "proc_injection_ptrace",
      "title": "Process injection via ptrace",
      "file": "rules/candidate/proc_injection_ptrace.yml",
      "attack": ["T1055.008"],
      "tactics": ["TA0004"],
      "level": "high",
      "status": "validated",
      "broken_reason": null,
      "unmapped_fields": [],
      "atomics": ["T1055.008-1"],
      "attack_windows": 2,
      "true_positives": 2,
      "missed": 0,
      "benign_windows": 400,
      "false_positives": 1,
      "fp_rate": 0.0025,
      "median_latency_ms": 340,
      "fp_examples": ["<raw audit line>"],
      "evasions": [
        {"variant": "renamed_binary", "atomic": "T1055.008-1", "evaded": true}
      ]
    }
  ],
  "coverage": {
    "tactics": {
      "TA0004": {
        "name": "Privilege Escalation",
        "techniques": {
          "T1055.008": {"status": "validated", "rules": 1}
        }
      }
    }
  },
  "worst_offenders": [
    {"rule": "suspicious_curl_pipe_sh", "fires": "2/2", "fp_rate": 0.081, "verdict": "too noisy"}
  ]
}
```

`status` on a technique in `coverage` is the best status among the rules claiming it, ordered `validated > partial > noisy > unfirable > broken > untested`. A technique with no rule at all is absent from the map and rendered as an outline cell.

## Schema 4: field mapping

The pipeline that maps Sigma field names onto the `events` columns lives in `engine/pipeline.py` and is the single source of truth for what is available.

| Sigma field | Column | Note |
|---|---|---|
| `Image`, `process.executable` | `exe` | |
| `CommandLine`, `process.command_line` | `cmdline` | |
| `ParentImage` | `parent_exe` | derived, NULL when parent exec unseen |
| `ParentCommandLine` | `parent_cmdline` | derived |
| `User` | `username` | |
| `CurrentDirectory` | `cwd` | |
| `ProcessId` / `ParentProcessId` | `pid` / `ppid` | |
| `TargetFilename` | `path` | |
| `DestinationIp` / `DestinationPort` | `dest_ip` / `dest_port` | |
| `a0` … `a7` | parsed argv positions | auditd-native rules |
| `exe`, `comm`, `key`, `syscall`, `auid`, `uid` | same name | auditd-native rules |

Anything not in that table is **unmapped**. A rule using an unmapped field is `broken`, and `unmapped_fields` names it. Bare keyword search maps to a `cmdline LIKE` scan; rules relying on keywords across the whole record are flagged, because that is not what the scan actually does.

## Query construction

pySigma's sqlite backend emits `SELECT * FROM <TABLE_NAME> WHERE <condition>`. The engine:

1. Extracts every field the rule references, recursively through nested detections.
2. Checks each against the mapping table. Any miss short circuits to `broken` and no query is run.
3. Applies the mapping to rename fields, then converts.
4. Wraps the emitted `WHERE` clause with the window bounds and `in_lab = 1` and the category implied by the rule's logsource.

Field availability is checked against the mapping table, not against the data. A field that is mapped but always NULL in this lab is a different and more interesting failure, and it shows up as `unfirable` rather than `broken`.

## Failure modes this design accepts

- The sensor sees the whole VM. If the user runs unrelated containers during a lab run, those events enter the database. They are excluded by `in_lab`, but they inflate `events_total`.
- Sentinel-delimited windows include everything the target did in that interval, including the shell that launched the activity. Rules matching on `/bin/sh` will fire on nearly every window. That is not a harness bug, it is the rule being bad, and it should show up as a high FP rate.
- auditd argv reconstruction loses the distinction between an argument containing a space and two arguments. The normalizer joins with a single space and records the original in `raw`.
- Techniques whose signal is not a syscall (anything purely in userspace memory, anything network-payload level) cannot be observed at all. Rules for them will be `unfirable` and that is honest.

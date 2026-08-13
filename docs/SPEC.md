# SPEC

## The problem

Detection rules are written once and then never checked again. Two failure modes follow from that.

The first is silent death. A rule that fired correctly last year stops firing because a log source renamed a field, or because the field it depends on was never populated in this environment to begin with. Nobody notices until an incident review.

The second is noise. A rule with a high false positive rate gets muted by the SOC inside a week. It still exists in the repo, it still shows up in coverage reports, and it detects nothing.

So for most rule sets, two questions have no answer: does this rule fire on the real technique, and how often does it fire on nothing.

## What this project does

It answers both questions for every rule, mechanically, from a single command.

The harness stands up a throwaway Linux lab, runs real attack techniques inside it, records the kernel telemetry that actually resulted, and then replays every rule against that telemetry. It does the same against a corpus of ordinary benign activity. Every rule ends up with a measured true positive count and a measured false positive rate instead of an assumption.

## Inputs

| Input | Form | Notes |
|---|---|---|
| Detection rules | Sigma YAML in `rules/candidate/` | One rule per file, tagged with `attack.tXXXX` |
| Attack definitions | `harness/atomics/*.yaml` | Locally curated, Atomic Red Team format and provenance |
| Benign activity definitions | `harness/profiles/benign/*.yaml` | Scripted ordinary sysadmin and CI behaviour |
| Threat intel | `intel/*.md` | Advisories and writeups used to author candidate rules |

## Outputs

| Output | Path | Notes |
|---|---|---|
| Normalized telemetry | `data/telemetry.db` | SQLite, one row per observed kernel event |
| Scoring results | `data/results.json` | The contract every downstream piece reads |
| Report | `docs/report.html` | Coverage matrix, FP chart, worst offenders |
| Hero image | `docs/hero.png` | Screenshot of `#hero` from the report |
| Findings | `FINDINGS.md` | Written from the real run |

## What it explicitly does not do

- No Windows telemetry. No Sysmon, no Windows Event Log. Rules written against Sysmon field names are collected and reported as broken, which is a deliberate demonstration and not an accident.
- Single host. No lateral movement, no network sensor, no east-west traffic. Anything requiring two hosts is out of scope.
- The benign corpus is synthetic. It was written by the same person who wrote the rules, so it is biased toward the noise that person thought to create.
- Not a production FP estimate. A few hundred benign windows is enough to separate a quiet rule from a loud one. It is not the millions of events a real SIEM sees, and the rate should be read as directional.
- No rule tuning loop. The harness measures. It does not automatically rewrite rules to improve their score.

## The measurement definitions

These are the definitions the whole project rests on, so they are stated before any code exists.

**Window.** A bounded interval of wall clock time inside the lab, with a label. An *attack window* is the interval during which one atomic test executed. A *benign window* is the interval during which one scripted benign activity executed. Windows do not overlap.

**Window boundaries are recorded in the sensor's own clock.** The executor does not read a clock and write down a timestamp. It executes a uniquely named sentinel process (`/bin/true __lab_window_start_<uuid>__`) which the sensor observes and records like any other event. The window is then delimited by the sentinel's own event timestamps. This removes clock skew between the orchestrator, the target container and the sensor container from the measurement entirely.

**True positive.** A rule fires at least once inside an attack window whose technique is one the rule claims to detect. Counted per window, not per event. A rule that fires 40 times in one attack window scores one true positive.

**Missed.** An attack window ran for a technique the rule claims, and the rule did not fire in it.

**False positive.** A rule fires inside a benign window. Counted per window.

**FP rate.** `false_positives / benign_windows`.

**Detection latency.** Milliseconds between the first event in the attack window and the earliest event that the rule matched. This measures how deep into the technique the rule sits, not how fast the pipeline is.

## Rule status taxonomy

Every rule lands in exactly one bucket. The taxonomy is the point of the project, so it is fixed here.

| Status | Meaning |
|---|---|
| `validated` | Fired in every attack window for its technique, FP rate at or under the noise threshold |
| `noisy` | Fired on the attack, but FP rate above the noise threshold |
| `partial` | Fired in some but not all attack windows for its technique |
| `unfirable` | Compiles, every field it uses exists in the telemetry, but it never fired on its own technique |
| `broken` | References at least one field the telemetry does not carry, so it cannot fire at all |
| `untested` | No atomic in the lab exercises the technique this rule claims |

Noise threshold: 1.0% FP rate. Stated up front so it cannot be moved after seeing the numbers.

## Success criteria

1. `make all` runs from a clean clone and regenerates `data/results.json`, the report and the hero image.
2. At least 40 rules carry a measured result.
3. At least one rule in the shipped report is marked `broken` because of a genuinely missing field, and the report names the field.
4. Every number in the README and FINDINGS traces to `data/results.json`.
5. Rules that stop firing fail CI.

## Non-negotiables

- The normalizer never invents a field. If auditd does not carry it, it is absent, and rules depending on it break. That failure is the product.
- Rules are authored and frozen before the harness runs against them. Rules are not edited to fit observed telemetry and then reported as validated.
- Reported numbers come from `data/results.json`. No number is typed by hand into prose.

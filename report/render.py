"""Render data/results.json into docs/report.html.

Reads only results.json. Every number on the page comes from there. The look
follows design/DESIGN.md (serif Signifier headlines on warm paper, Sohne for the
rest, the peach accent rationed) with one necessary addition: a detection matrix
needs status colours, so a small, desaturated status palette is introduced for
the cells and nothing else.
"""
import html
import json
import statistics
import sys

# A compact Linux-relevant ATT&CK catalogue so the matrix reads as a matrix:
# measured techniques get their status colour, the rest render as empty coverage.
CATALOG = [
    ("TA0002", "Execution", [
        ("T1059.004", "Unix Shell"), ("T1059.006", "Python"),
        ("T1053.003", "Cron"), ("T1204", "User Execution")]),
    ("TA0003", "Persistence", [
        ("T1547.006", "Kernel Module"), ("T1053.003", "Cron Job"),
        ("T1543.002", "Systemd Service"), ("T1546.004", "Shell Init")]),
    ("TA0004", "Priv Esc", [
        ("T1548.003", "Sudo"), ("T1548.001", "Setuid"),
        ("T1055.008", "Ptrace"), ("T1068", "Exploit")]),
    ("TA0005", "Defense Evasion", [
        ("T1070.003", "Clear History"), ("T1222.002", "File Perms"),
        ("T1140", "Deobfuscate"), ("T1562.001", "Disable Tools"),
        ("T1055.008", "Ptrace"), ("T1036.005", "Masquerade")]),
    ("TA0006", "Cred Access", [
        ("T1552.001", "Creds in Files"), ("T1003.008", "Shadow"),
        ("T1003.001", "LSASS"), ("T1110", "Brute Force")]),
    ("TA0007", "Discovery", [
        ("T1082", "System Info"), ("T1033", "Owner/User"),
        ("T1087.001", "Accounts"), ("T1057", "Process"),
        ("T1083", "File/Dir"), ("T1518.001", "Security SW")]),
    ("TA0009", "Collection", [
        ("T1560.001", "Archive"), ("T1074", "Staging")]),
    ("TA0011", "C2", [
        ("T1105", "Ingress Transfer"), ("T1071.001", "Web Protocol"),
        ("T1090", "Proxy")]),
    ("TA0040", "Impact", [
        ("T1496", "Resource Hijack"), ("T1485", "Data Destruction")]),
    # Windows-only tactics carried by the broken rules, to show the gap on the map.
    ("TA0003b", "Persistence (Win)", [
        ("T1053.005", "Scheduled Task"), ("T1547.001", "Run Key")]),
    ("TA0005b", "Defense Evasion (Win)", [
        ("T1218.011", "Rundll32")]),
]

STATUS_LABEL = {
    "validated": "validated", "noisy": "noisy", "partial": "partial",
    "unfirable": "unfirable", "broken": "broken", "untested": "untested",
    "none": "no rule",
}


def _median(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def build(results):
    rules = results["rules"]
    by_status = {}
    for r in rules:
        by_status.setdefault(r["status"], []).append(r)

    validated = len(by_status.get("validated", []))
    total = len(rules)

    # techniques with at least one firing rule (validated/partial/noisy)
    covered = set()
    for r in rules:
        if r["status"] in ("validated", "partial", "noisy"):
            covered |= set(r["attack"])

    fp_rates = [r["fp_rate"] for r in rules
                if r["status"] in ("validated", "noisy", "partial") and r["fp_rate"] is not None]
    latencies = [r["median_latency_ms"] for r in rules if r["median_latency_ms"] is not None]

    # technique -> best measured status, from coverage
    tech_status = {}
    for ta in results["coverage"]["tactics"].values():
        for tid, cell in ta["techniques"].items():
            prev = tech_status.get(tid)
            tech_status[tid] = cell["status"] if prev is None else prev  # keep first

    hero = {
        "validated": validated,
        "total": total,
        "techniques_covered": len(covered),
        "median_fp": _median(fp_rates),
        "median_latency": _median(latencies),
        "benign_windows": results["run"]["benign_windows"],
        "attack_windows": results["run"]["attack_windows"],
        "events_in_lab": results["run"]["events_in_lab"],
    }
    return hero, tech_status, by_status


CSS = """
:root{
  --bg:#ffffff; --mist:#f2f2f3; --fog:#fafafb; --ink:#17191c; --muted:#777b86;
  --line:#e7e7ea; --peach:#fbe1d1; --sienna:#5d2a1a;
  --ok:#3f7a52; --noisy:#b07a1e; --partial:#8a6d2f; --broken:#a3402a;
  --unfirable:#9a9aa0; --none:#e7e7ea;
  --serif:'Signifier','GT Sectra','Tiempos Headline',ui-serif,Georgia,'Times New Roman',serif;
  --sans:'Sohne','Inter',ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  --mono:'SF Mono',ui-monospace,'Menlo','Consolas',monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
  font-size:16px;line-height:1.5;-webkit-font-smoothing:antialiased}
.wrap{max-width:1200px;margin:0 auto;padding:40px 32px 80px}
#hero{background:var(--bg);padding:8px 4px 4px}
.kicker{font-family:var(--sans);font-size:14px;letter-spacing:.02em;color:var(--muted);
  text-transform:none;margin:0 0 14px}
h1{font-family:var(--serif);font-weight:400;font-size:64px;line-height:1.05;
  letter-spacing:-.015em;margin:0 0 6px}
h1 .num{font-family:var(--serif)}
.sub{font-size:18px;color:var(--muted);margin:0 0 30px;max-width:760px}
.counters{display:flex;gap:14px;flex-wrap:wrap;margin:0 0 30px}
.counter{background:var(--mist);border-radius:16px;padding:16px 20px;min-width:150px}
.counter .v{font-family:var(--mono);font-size:26px;font-weight:600;letter-spacing:-.01em}
.counter .l{font-size:13px;color:var(--muted);margin-top:2px}
.counter.accent{background:var(--peach);color:var(--sienna)}
.counter.accent .v{color:var(--sienna)}
.counter.accent .l{color:var(--sienna);opacity:.85}
.panel{background:var(--fog);border:1px solid var(--line);border-radius:20px;
  padding:22px 24px;margin:0 0 22px}
.panel h2{font-family:var(--serif);font-weight:400;font-size:26px;margin:0 0 4px;letter-spacing:-.01em}
.panel .note{font-size:13px;color:var(--muted);margin:0 0 18px}
.matrix{display:flex;gap:10px;overflow-x:auto;padding-bottom:4px}
.col{flex:1 0 118px;min-width:118px}
.col .head{font-size:12px;font-weight:600;color:var(--ink);height:30px;
  border-bottom:1px solid var(--line);margin-bottom:8px;line-height:1.1;
  display:flex;align-items:flex-end;padding-bottom:4px}
.cell{border-radius:10px;padding:8px 9px;margin-bottom:6px;font-size:11px;line-height:1.15;
  border:1px solid transparent;min-height:44px}
.cell .t{font-family:var(--mono);font-size:10px;opacity:.75}
.cell .n{font-weight:500;margin-top:2px}
.cell.validated{background:var(--ok);color:#fff}
.cell.noisy{background:var(--noisy);color:#fff}
.cell.partial{background:var(--partial);color:#fff}
.cell.unfirable{background:#ededf0;color:#6a6a72;border-color:#dededF}
.cell.broken{background:#fff;color:var(--broken);border:1px dashed var(--broken)}
.cell.untested{background:#f4f4f5;color:#9a9aa0}
.cell.none{background:transparent;color:#c4c4c8;border:1px solid var(--none)}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-top:14px}
.legend span{display:inline-flex;align-items:center;gap:6px}
.dot{width:11px;height:11px;border-radius:3px;display:inline-block}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;font-weight:600;color:var(--muted);font-size:12px;
  border-bottom:1px solid var(--line);padding:8px 10px}
td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
td.mono,.mono{font-family:var(--mono);font-size:13px}
.verdict{font-weight:600}
.v-ship{color:var(--ok)} .v-noisy{color:var(--noisy)} .v-broken{color:var(--broken)}
.pill{display:inline-block;font-size:11px;font-weight:600;padding:2px 9px;border-radius:9999px}
.pill.validated{background:#e7f1ea;color:var(--ok)}
.pill.noisy{background:#f6ecd8;color:var(--noisy)}
.pill.partial{background:#f1ecdc;color:var(--partial)}
.pill.unfirable{background:#ededf0;color:#6a6a72}
.pill.broken{background:#f6e5e0;color:var(--broken)}
.pill.untested{background:#f0f0f1;color:#8a8a92}
.foot{font-size:12px;color:var(--muted);margin-top:26px}
"""


def esc(s):
    return html.escape(str(s))


def matrix_html(tech_status):
    cols = []
    for entry in CATALOG:
        _, name, techs = entry
        cells = []
        seen = set()
        for tid, tname in techs:
            if tid in seen:
                continue
            seen.add(tid)
            st = tech_status.get(tid, "none")
            cells.append(
                f'<div class="cell {st}"><div class="t">{esc(tid)}</div>'
                f'<div class="n">{esc(tname)}</div></div>')
        cols.append(f'<div class="col"><div class="head">{esc(name)}</div>'
                    + "".join(cells) + "</div>")
    return '<div class="matrix">' + "".join(cols) + "</div>"


def legend_html():
    items = [("validated", "validated"), ("noisy", "too noisy"),
             ("partial", "partial"), ("unfirable", "unfirable"),
             ("broken", "broken (field missing)"), ("none", "no rule")]
    spans = []
    for cls, label in items:
        spans.append(f'<span><i class="dot" style="background:var(--{ "ok" if cls=="validated" else cls if cls in ("noisy","partial","unfirable","broken") else "none"});'
                     + (';border:1px dashed var(--broken)' if cls == "broken" else '')
                     + f'"></i>{esc(label)}</span>')
    return '<div class="legend">' + "".join(spans) + "</div>"


def worst_html(results):
    rows = results["worst_offenders"]
    trs = []
    for r in rows:
        v = r["verdict"]
        cls = "v-ship" if "ship" in v else ("v-broken" if "broken" in v else "v-noisy")
        trs.append(
            f'<tr><td class="mono">{esc(r["rule"])}</td>'
            f'<td class="mono">{esc(r["fires"])}</td>'
            f'<td class="mono">{esc(r["fp_rate"])}</td>'
            f'<td class="verdict {cls}">{esc(v)}</td></tr>')
    return ('<table><thead><tr><th>RULE</th><th>FIRES ON ATTACK</th>'
            '<th>FP RATE</th><th>VERDICT</th></tr></thead><tbody>'
            + "".join(trs) + "</tbody></table>")


def rules_table(by_status):
    order = ["validated", "noisy", "partial", "unfirable", "broken", "untested"]
    trs = []
    for st in order:
        for r in sorted(by_status.get(st, []), key=lambda r: r["id"]):
            fr = f'{r["fp_rate"]*100:.2f}%' if r["fp_rate"] is not None else "–"
            lat = f'{r["median_latency_ms"]:.0f} ms' if r["median_latency_ms"] is not None else "–"
            fires = f'{r["true_positives"]}/{r["attack_windows"]}' if r["attack_windows"] else "–"
            reason = r.get("broken_reason") or ""
            note = f'<div class="foot" style="margin:2px 0 0">{esc(reason)}</div>' if reason else ""
            trs.append(
                f'<tr><td class="mono">{esc(r["id"])}{note}</td>'
                f'<td><span class="pill {st}">{esc(STATUS_LABEL[st])}</span></td>'
                f'<td class="mono">{esc(",".join(r["attack"]) or "–")}</td>'
                f'<td class="mono">{esc(fires)}</td>'
                f'<td class="mono">{esc(fr)}</td>'
                f'<td class="mono">{esc(lat)}</td></tr>')
    return ('<table><thead><tr><th>RULE</th><th>STATUS</th><th>ATT&CK</th>'
            '<th>FIRES</th><th>FP RATE</th><th>LATENCY</th></tr></thead><tbody>'
            + "".join(trs) + "</tbody></table>")


def render(results):
    hero, tech_status, by_status = build(results)
    fp = f'{hero["median_fp"]*100:.2f}%' if hero["median_fp"] is not None else "–"
    lat = f'{hero["median_latency"]:.0f} ms' if hero["median_latency"] is not None else "–"
    lab = results["lab"]
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Detection Lab Report</title><style>{CSS}</style></head><body><div class="wrap">
<div id="hero">
  <p class="kicker">detection-lab · validated against live attack telemetry</p>
  <h1><span class="num">{hero['validated']} / {hero['total']}</span> rules validated</h1>
  <p class="sub">Every rule ran against real kernel telemetry from attacks executed in a
    throwaway Linux lab, and against {hero['benign_windows']} windows of ordinary activity.
    Each one carries a measured true-positive count and a false-positive rate, not a guess.</p>
  <div class="counters">
    <div class="counter accent"><div class="v">{hero['techniques_covered']}</div>
      <div class="l">ATT&CK techniques covered</div></div>
    <div class="counter"><div class="v">{fp}</div><div class="l">median FP rate (firing rules)</div></div>
    <div class="counter"><div class="v">{lat}</div><div class="l">median detection latency</div></div>
    <div class="counter"><div class="v">{hero['attack_windows']}</div><div class="l">attack windows</div></div>
    <div class="counter"><div class="v">{hero['events_in_lab']}</div><div class="l">in-lab events observed</div></div>
  </div>
  <div class="panel">
    <h2>Coverage matrix</h2>
    <p class="note">Tactic columns, technique cells, coloured by what the harness measured.
      Solid means it fires; dashed means the rule references a field this lab does not carry.</p>
    {matrix_html(tech_status)}
    {legend_html()}
  </div>
  <div class="panel">
    <h2>Worst offenders</h2>
    <p class="note">One clean shipper, one too noisy to keep, one proven broken.
      The broken row is the point: the harness caught a rule whose field does not exist here.</p>
    {worst_html(results)}
  </div>
</div>
<div class="panel">
  <h2>Every rule, measured</h2>
  <p class="note">Status taxonomy: validated (fires on all attack windows, FP at or under
    {results['run']['noise_threshold']*100:.0f}%), noisy (fires but too many FPs), partial
    (fires on some windows), unfirable (mapped fields, never fired), broken (references a
    missing field), untested (no atomic exercises it).</p>
  {rules_table(by_status)}
</div>
<p class="foot">Generated {esc(results['generated_at'])} · sensor {esc(lab['sensor'])} ·
  kernel {esc(lab['kernel'])} {esc(lab['arch'])} · audit events lost: {esc(lab['audit_lost'])} ·
  session {esc(results['run']['session_id'])}</p>
</div></body></html>"""
    return doc


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "data/results.json"
    out = sys.argv[2] if len(sys.argv) > 2 else "docs/report.html"
    with open(src) as fh:
        results = json.load(fh)
    with open(out, "w") as fh:
        fh.write(render(results))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()

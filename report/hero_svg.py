"""Render the hero panel straight to an SVG from results.json.

The intended pipeline is report.html then a headless screenshot to hero.png (see
shoot.py). On a machine with no browser engine available, this produces the same
hero as a vector image instead, so the README still opens on the real numbers and
the picture always matches the data it was built from. Every value comes from
results.json.

    python report/hero_svg.py data/results.json docs/hero.svg
"""
import html
import json
import sys

from report.render import build, CATALOG

W = 1400
COLORS = {
    "validated": "#3f7a52", "noisy": "#b07a1e", "partial": "#8a6d2f",
    "unfirable": "#ededf0", "broken": "#ffffff", "untested": "#f4f4f5",
    "none": "#ffffff",
}
TEXTC = {
    "validated": "#ffffff", "noisy": "#ffffff", "partial": "#ffffff",
    "unfirable": "#6a6a72", "broken": "#a3402a", "untested": "#9a9aa0",
    "none": "#c4c4c8",
}


def esc(s):
    return html.escape(str(s))


def render_svg(results):
    hero, tech_status, _ = build(results)
    fp = f'{hero["median_fp"]*100:.2f}%' if hero["median_fp"] is not None else "-"
    lat = f'{hero["median_latency"]:.0f} ms' if hero["median_latency"] is not None else "-"
    S = []
    SERIF = "Georgia,'Times New Roman',serif"
    SANS = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
    MONO = "'SF Mono',Menlo,Consolas,monospace"

    def text(x, y, s, size, color="#17191c", family=SANS, weight="400", anchor="start"):
        S.append(f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" '
                 f'font-weight="{weight}" fill="{color}" text-anchor="{anchor}">{esc(s)}</text>')

    def rect(x, y, w, h, fill, rx=10, stroke="none", dash=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        S.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" '
                 f'fill="{fill}" stroke="{stroke}" stroke-width="1"{d}/>')

    # kicker + headline
    text(48, 52, "detection-lab  ·  validated against live attack telemetry", 15, "#777b86")
    text(46, 118, f"{hero['validated']} / {hero['total']}", 66, "#17191c", SERIF)
    hw = 60 + len(f"{hero['validated']} / {hero['total']}") * 40
    text(hw, 118, "rules validated", 40, "#17191c", SERIF)
    text(48, 156, "Every rule ran against real kernel telemetry from attacks in a throwaway Linux "
                  f"lab, and against {hero['benign_windows']} windows of ordinary activity.", 16, "#777b86")
    text(48, 180, "Each carries a measured true-positive count and a false-positive rate, not a guess.",
         16, "#777b86")

    # counters
    counters = [
        (str(hero["techniques_covered"]), "ATT&CK techniques covered", True),
        (fp, "median FP rate (firing rules)", False),
        (lat, "median detection latency", False),
        (str(hero["attack_windows"]), "attack windows", False),
        (str(hero["events_in_lab"]), "in-lab events observed", False),
    ]
    cx, cy, cw, ch, gap = 48, 208, 252, 74, 12
    for val, lab, accent in counters:
        rect(cx, cy, cw, ch, "#fbe1d1" if accent else "#f2f2f3", rx=16)
        tc = "#5d2a1a" if accent else "#17191c"
        text(cx + 18, cy + 34, val, 26, tc, MONO, "600")
        text(cx + 18, cy + 56, lab, 13, "#5d2a1a" if accent else "#777b86")
        cx += cw + gap

    # matrix
    my = 322
    text(48, my, "Coverage matrix", 26, "#17191c", SERIF)
    text(48, my + 22, "Tactic columns, technique cells, coloured by what the harness measured. "
         "Dashed = the rule names a field this lab does not carry.", 14, "#777b86")
    grid_y = my + 44
    n = len(CATALOG)
    colw = (W - 96) / n
    for i, (_, name, techs) in enumerate(CATALOG):
        x = 48 + i * colw
        text(x, grid_y, name[:16], 11, "#17191c", SANS, "600")
        S.append(f'<line x1="{x}" y1="{grid_y+6}" x2="{x+colw-8}" y2="{grid_y+6}" '
                 f'stroke="#e7e7ea" stroke-width="1"/>')
        cyy = grid_y + 16
        seen = set()
        for tid, tname in techs:
            if tid in seen:
                continue
            seen.add(tid)
            st = tech_status.get(tid, "none")
            fill = COLORS[st]
            stroke = "#a3402a" if st == "broken" else ("#dedee1" if st in ("unfirable", "none") else "none")
            dash = "3 2" if st == "broken" else None
            rect(x, cyy, colw - 8, 40, fill, rx=8, stroke=stroke, dash=dash)
            text(x + 8, cyy + 16, tid, 9.5, TEXTC[st], MONO)
            text(x + 8, cyy + 30, tname[:13], 10, TEXTC[st], SANS, "500")
            cyy += 46

    # legend
    ly = grid_y + 16 + 6 * 46 + 18
    legend = [("validated", "validated"), ("noisy", "too noisy"), ("partial", "partial"),
              ("unfirable", "unfirable"), ("broken", "broken (field missing)"), ("none", "no rule")]
    lx = 48
    for st, label in legend:
        stroke = "#a3402a" if st == "broken" else ("#dedee1" if st in ("unfirable", "none") else "none")
        rect(lx, ly - 10, 12, 12, COLORS[st], rx=3, stroke=stroke,
             dash="3 2" if st == "broken" else None)
        text(lx + 18, ly, label, 12.5, "#777b86")
        lx += 40 + len(label) * 7.2

    # worst offenders
    wy = ly + 40
    text(48, wy, "Worst offenders", 26, "#17191c", SERIF)
    text(48, wy + 22, "One clean shipper, one too noisy to keep, one proven broken. The broken row is "
         "the point.", 14, "#777b86")
    ty = wy + 46
    cols = [(48, "RULE"), (620, "FIRES ON ATTACK"), (900, "FP RATE"), (1120, "VERDICT")]
    for x, hlabel in cols:
        text(x, ty, hlabel, 12, "#777b86", SANS, "600")
    S.append(f'<line x1="48" y1="{ty+8}" x2="{W-48}" y2="{ty+8}" stroke="#e7e7ea"/>')
    ry = ty + 34
    for row in results["worst_offenders"]:
        v = row["verdict"]
        vc = "#3f7a52" if "ship" in v else ("#a3402a" if "broken" in v else "#b07a1e")
        text(48, ry, row["rule"], 15, "#17191c", MONO)
        text(620, ry, row["fires"], 15, "#17191c", MONO)
        text(900, ry, row["fp_rate"], 15, "#17191c", MONO)
        text(1120, ry, v, 15, vc, SANS, "600")
        S.append(f'<line x1="48" y1="{ry+12}" x2="{W-48}" y2="{ry+12}" stroke="#f0f0f1"/>')
        ry += 40

    H = ry + 20
    head = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
            f'viewBox="0 0 {W} {H}">')
    bg = f'<rect x="0" y="0" width="{W}" height="{H}" fill="#ffffff"/>'
    return head + bg + "".join(S) + "</svg>"


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "data/results.json"
    out = sys.argv[2] if len(sys.argv) > 2 else "docs/hero.svg"
    with open(src) as fh:
        results = json.load(fh)
    with open(out, "w") as fh:
        fh.write(render_svg(results))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()

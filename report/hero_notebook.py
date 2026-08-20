"""Field-notebook hero: the 24 candidate rules before and after the lab ran.

Renders straight to SVG from results.json, in the idiom of a marked-up
notebook page rather than a dashboard. Deterministic: the pen wobble is
seeded, so regenerating from the same results gives a byte-identical file.

    python -m report.hero_notebook data/results.json docs/hero-notebook.svg
"""
import json
import math
import random
import sys

W, H = 2000, 1000

PAPER = "#F7F2E7"
RULE_BLUE = "#C4D3E2"
MARGIN_RED = "#D9948C"
INK = "#23211E"
GRAY = "#7C766C"

HAND = "Bradley Hand, Chalkboard SE, Segoe Print, Comic Sans MS, cursive"
NOTE = "Chalkboard SE, Bradley Hand, Comic Sans MS, cursive"

# bucket -> (label, blurb, colour, mark)
BUCKETS = [
    ("validated", "fired every attack window, 1% false positives or less", "#3F6B4A", "check"),
    ("noisy",     "fired, but up to 17.3% false positives", "#B07A2E", "squiggle"),
    ("unfirable", "every field present. never fired once.", "#8A857C", "dash"),
    ("broken",    "wants a log field this box does not have", "#A33D33", "cross"),
    ("partial",   "fired on some attack windows, not all", "#4A6B8A", "half"),
]


def esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


class Pen:
    """Rough, hand-drawn primitives on a seeded RNG."""

    def __init__(self, seed=0xB1AC):
        self.r = random.Random(seed)
        self.out = []

    def j(self, a):
        return self.r.uniform(-a, a)

    def _seg(self, ax, ay, bx, by, w):
        mx = (ax + bx) / 2 + self.j(w * 1.7)
        my = (ay + by) / 2 + self.j(w * 1.7)
        return "Q%.1f,%.1f %.1f,%.1f " % (mx, my, bx, by)

    def line(self, x1, y1, x2, y2, color=INK, sw=2.4, wob=1.7, passes=1, op=1.0):
        for _ in range(passes):
            ax, ay = x1 + self.j(wob), y1 + self.j(wob)
            bx, by = x2 + self.j(wob), y2 + self.j(wob)
            d = "M%.1f,%.1f " % (ax, ay) + self._seg(ax, ay, bx, by, wob)
            self.out.append(
                '<path d="%s" fill="none" stroke="%s" stroke-width="%.1f" '
                'stroke-linecap="round" opacity="%.2f"/>' % (d, color, sw, op))

    def rect(self, x, y, w, h, color=INK, sw=2.2, wob=1.5, passes=2, op=1.0):
        for _ in range(passes):
            c = [(x, y), (x + w, y), (x + w, y + h), (x, y + h)]
            c = [(px + self.j(wob), py + self.j(wob)) for px, py in c]
            d = "M%.1f,%.1f " % c[0]
            for i in range(4):
                a, b = c[i], c[(i + 1) % 4]
                d += self._seg(a[0], a[1], b[0], b[1], wob)
            self.out.append(
                '<path d="%s" fill="none" stroke="%s" stroke-width="%.1f" '
                'stroke-linejoin="round" stroke-linecap="round" opacity="%.2f"/>'
                % (d, color, sw, op))

    def arrow(self, x1, y1, x2, y2, color=INK, sw=3.0, head=16):
        self.line(x1, y1, x2, y2, color, sw, 2.0, passes=2)
        ang = math.atan2(y2 - y1, x2 - x1)
        for s in (+1, -1):
            a = ang + s * 2.55
            self.line(x2, y2, x2 + head * math.cos(a), y2 + head * math.sin(a),
                      color, sw, 1.2, passes=1)

    def text(self, x, y, s, size=24, color=INK, font=HAND, anchor="start", op=1.0, rot=None):
        tr = ' transform="rotate(%.1f %.1f %.1f)"' % (rot, x, y) if rot else ""
        self.out.append(
            '<text x="%.1f" y="%.1f" font-family="%s" font-size="%.1f" fill="%s" '
            'text-anchor="%s" opacity="%.2f"%s>%s</text>'
            % (x, y, font, size, color, anchor, op, tr, esc(s)))

    # --- marks that go inside a rule box -------------------------------
    def mark(self, kind, x, y, s, color):
        cx, cy = x + s / 2, y + s / 2
        if kind == "check":
            self.line(cx - s * .27, cy + s * .02, cx - s * .07, cy + s * .22, color, 3.4, 1.0)
            self.line(cx - s * .07, cy + s * .22, cx + s * .29, cy - s * .25, color, 3.4, 1.0)
        elif kind == "cross":
            self.line(cx - s * .24, cy - s * .24, cx + s * .24, cy + s * .24, color, 3.2, 1.2)
            self.line(cx + s * .24, cy - s * .24, cx - s * .24, cy + s * .24, color, 3.2, 1.2)
        elif kind == "squiggle":
            pts, n = [], 11
            for i in range(n):
                pts.append((x + s * .15 + (s * .70) * i / (n - 1),
                            cy + (s * .15 if i % 2 else -s * .15) + self.j(0.8)))
            d = "M%.1f,%.1f " % pts[0]
            for i in range(len(pts) - 1):
                d += self._seg(pts[i][0], pts[i][1], pts[i + 1][0], pts[i + 1][1], 1.0)
            self.out.append('<path d="%s" fill="none" stroke="%s" stroke-width="2.8" '
                            'stroke-linecap="round"/>' % (d, color))
        elif kind == "dash":
            self.line(cx - s * .24, cy, cx + s * .24, cy, color, 3.0, 1.0)
        elif kind == "half":
            for i in range(3):
                off = s * (.22 + i * .19)
                self.line(x + off, y + s * .78, x + s * .78, y + off, color, 2.4, 1.0)

    def svg(self):
        return "\n".join(self.out)


def paper(p):
    """Ruled lines and the red margin, drawn first."""
    for i in range(1, 22):
        yy = 60 + i * 44
        p.line(0, yy, W, yy, RULE_BLUE, 1.6, 1.1, op=0.55)
    p.line(146, 0, 146, H, MARGIN_RED, 2.0, 1.6, op=0.75)
    p.line(153, 0, 153, H, MARGIN_RED, 1.4, 1.6, op=0.45)


def build(counts, total, events, dropped, attacks, benign):
    p = Pen()
    p.out.append('<rect width="%d" height="%d" fill="%s"/>' % (W, H, PAPER))
    paper(p)

    # ---- headline ----------------------------------------------------
    p.text(190, 116, "%d rules went in. %d came out clean." % (total, counts["validated"]), 70)
    p.text(194, 168,
           "Every Sigma rule in this repo, run against live attack telemetry from a throwaway Linux lab.",
           26, GRAY, NOTE)

    # ---- left panel: what the repo shows ------------------------------
    p.text(190, 252, "what the repo shows", 34)
    p.line(190, 264, 470, 264, INK, 2.0, 2.0)

    bs, gap, cols = 80, 20, 6
    gx, gy = 190, 292
    for i in range(total):
        c, r = i % cols, i // cols
        bx, by = gx + c * (bs + gap), gy + r * (bs + gap)
        p.rect(bx, by, bs, bs, INK, 2.0, 1.5)
        # faint ruled lines inside, so each box reads as a rule file
        for k in range(3):
            p.line(bx + bs * .17, by + bs * .30 + k * bs * .20,
                   bx + bs * (.83 if k < 2 else .60), by + bs * .30 + k * bs * .20,
                   INK, 1.5, 1.0, op=0.32)
    grid_r = gx + cols * (bs + gap) - gap
    grid_b = gy + 4 * (bs + gap) - gap

    p.text(190, grid_b + 46, "%d plausible rules, all committed," % total, 24, GRAY, NOTE)
    p.text(190, grid_b + 78, "every one of them looking like coverage.", 24, GRAY, NOTE)

    # ---- the arrow ----------------------------------------------------
    mid = (grid_r + 980) / 2
    p.arrow(grid_r + 24, 470, 964, 470, INK, 3.2, 18)
    p.text(mid, 516, "%d real attacks" % attacks, 19, INK, NOTE, anchor="middle")
    p.text(mid, 543, "%d benign windows" % benign, 19, INK, NOTE, anchor="middle")

    # ---- right panel: what actually happened --------------------------
    rx = 980
    p.text(rx, 252, "what actually happened", 34)
    p.line(rx, 264, rx + 300, 264, INK, 2.0, 2.0)

    row_h, ry0 = 100, 292
    mb, mg, mx0 = 38, 8, 1520
    broken_anchor = None
    for i, (key, blurb, color, kind) in enumerate(BUCKETS):
        n = counts.get(key, 0)
        ry = ry0 + i * row_h
        p.text(rx, ry + 48, str(n), 56, color)
        p.text(rx + 74, ry + 32, key, 31, INK)
        p.text(rx + 74, ry + 62, blurb, 19, GRAY, NOTE)
        for k in range(n):
            bx = mx0 + k * (mb + mg)
            p.rect(bx, ry + 14, mb, mb, color, 1.8, 1.1)
            p.mark(kind, bx, ry + 14, mb, color)
        if key == "broken":
            broken_anchor = (mx0 + (n * (mb + mg) - mg) / 2, ry + 14 + mb)

    # ---- footnotes ----------------------------------------------------
    p.line(190, 840, 1930, 840, RULE_BLUE, 1.8, 1.4, op=0.85)

    p.text(208, 900, "%s audit events collected." % format(events, ","), 24, INK, NOTE)
    p.text(208, 934, "%d dropped by the kernel." % dropped, 24, INK, NOTE)
    p.rect(190, 866, 412, 88, INK, 1.8, 2.6, passes=2, op=0.5)

    p.text(668, 890, "* 2 of the 3 rules I tried to evade fell to one command:", 23, INK, NOTE)
    p.text(668, 924, "cp /bin/sh /tmp/x", 24, "#A33D33", "Menlo, Courier New, monospace")
    p.text(668, 956, "A rule that matches on binary path goes blind.", 23, GRAY, NOTE)

    if broken_anchor:
        bx, by = broken_anchor
        p.arrow(1668, 854, bx + 8, by + 14, "#A33D33", 2.4, 13)
    p.text(1930, 900, "Windows rules on a Linux box.", 23, "#A33D33", NOTE, anchor="end")
    p.text(1930, 934, "Nothing errors. They just never fire.", 23, "#A33D33", NOTE, anchor="end")

    return ('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
            'viewBox="0 0 %d %d">\n%s\n</svg>\n' % (W, H, W, H, p.svg()))


def main(src, dst):
    r = json.load(open(src))
    counts = {}
    for rule in r["rules"]:
        counts[rule["status"]] = counts.get(rule["status"], 0) + 1
    run = r.get("run", {})
    lab = r.get("lab", {})
    events = run["events_total"]
    dropped = lab.get("audit_lost", 0)
    attacks = run["attack_windows"]
    benign = run["benign_windows"]
    svg = build(counts, len(r["rules"]), events, dropped, attacks, benign)
    open(dst, "w").write(svg)
    print("wrote %s (%d rules: %s)" % (dst, len(r["rules"]), counts))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "data/results.json",
         sys.argv[2] if len(sys.argv) > 2 else "docs/hero-notebook.svg")

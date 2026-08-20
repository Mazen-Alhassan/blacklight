#!/bin/zsh
# render a WxH svg to a crisp WxH png via qlmanage (which renders 2x into a square canvas)
set -e
SRC="$1"; OUT="$2"; W="$3"; H="$4"
TMP=$(mktemp -d)
PAD=$(( (W - H) / 2 ))
python3 - "$SRC" "$TMP/sq.svg" "$W" "$H" "$PAD" <<'PY'
import sys, re
src, dst, W, H, PAD = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
s = open(src).read()
inner = re.sub(r'^.*?<svg[^>]*>', '', s, flags=re.S).replace('</svg>', '')
open(dst, 'w').write(
 '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">'
 '<rect width="%d" height="%d" fill="#F7F2E7"/><g transform="translate(0,%d)">%s</g></svg>'
 % (W, W, W, W, W, W, PAD, inner))
PY
qlmanage -t -s $((W*2)) -o "$TMP" "$TMP/sq.svg" >/dev/null 2>&1
BIG="$TMP/sq.svg.png"
sips -c $((H*2)) $((W*2)) "$BIG" --out "$TMP/crop.png" >/dev/null 2>&1
sips --resampleWidth "$W" "$TMP/crop.png" --out "$OUT" >/dev/null 2>&1
sips -g pixelWidth -g pixelHeight "$OUT" | tail -2
rm -rf "$TMP"

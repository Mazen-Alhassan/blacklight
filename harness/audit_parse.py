"""Parse the raw auditd log into grouped audit events.

The raw log format, learned by capturing a real one on the lab kernel:

- One line per record: `type=X msg=audit(<epoch>:<serial>): <fields>`.
- Records that share a serial belong to one audit event (SYSCALL + EXECVE + CWD
  + PATH + PROCTITLE + SOCKADDR).
- audispd enrichment is on, so each raw line has UPPERCASE enriched fields
  appended after a 0x1d group-separator byte. We split on 0x1d and keep the raw
  lowercase fields, using the enriched `SYSCALL=` only as a syscall-name fallback.
- String values are double-quoted when printable and hex-encoded when they carry
  spaces or NULs. EXECVE argv follows that rule per argument.

This module produces raw grouped events. It does not categorize, scope or decide
what a field means. That is the normalizer's job.
"""
import re
from collections import defaultdict

HEADER = re.compile(r"^type=(\w+) msg=audit\(([\d.]+):(\d+)\):\s*(.*)$")

# aarch64 and x86_64 numbers for the syscalls the lab audits, so parsing does not
# depend on audispd enrichment being present.
SYSCALL_NUM = {
    "aarch64": {221: "execve", 281: "execveat", 203: "connect", 117: "ptrace",
                105: "init_module", 273: "finit_module", 56: "openat", 257: "openat"},
    "x86_64": {59: "execve", 322: "execveat", 42: "connect", 101: "ptrace",
               175: "init_module", 313: "finit_module", 257: "openat", 2: "open"},
}
ARCH_NAME = {"c00000b7": "aarch64", "c000003e": "x86_64"}

UNSET = 4294967295


def _decode_value(v):
    """Decode one raw audit field value: quoted string, hex blob, or bare token."""
    if v is None:
        return None
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    if v == "(none)" or v == "?":
        return None
    # Hex-encoded string: even length, all hex, and long enough to not be a small
    # integer field. argv/proctitle/paths arrive this way when they hold spaces.
    if len(v) >= 2 and len(v) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", v):
        try:
            return bytes.fromhex(v).replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except ValueError:
            return v
    return v


def _tokenize(rest):
    """Raw audit fields are space separated; quoted values never contain spaces
    (paths with spaces are hex-encoded), so a plain split is safe."""
    out = {}
    for tok in rest.split(" "):
        if not tok or "=" not in tok:
            continue
        k, _, val = tok.partition("=")
        out.setdefault(k, val)  # first wins; enriched UPPERCASE duplicates ignored
    return out


def _execve_cmdline(rest):
    """Reconstruct argv from an EXECVE record, handling split args a1[0], a1[1]."""
    # Pull argc then a0..a{argc-1}, each possibly quoted or hex.
    parts = defaultdict(dict)
    for m in re.finditer(r"\ba(\d+)(?:\[(\d+)\])?=(\"[^\"]*\"|\S+)", rest):
        idx, sub, val = int(m.group(1)), m.group(2), m.group(3)
        parts[idx][int(sub) if sub is not None else 0] = val
    args = []
    for idx in sorted(parts):
        joined = "".join(parts[idx][s] for s in sorted(parts[idx]))
        args.append(_decode_value(joined) or "")
    return " ".join(args)


def parse_log(path):
    """Yield one dict per audit event (grouped by serial), preserving raw text."""
    groups = {}
    order = []
    with open(path, "rb") as fh:
        data = fh.read()
    # 0x1d separates raw fields from the enriched suffix. Turning it into a space
    # lets the tokenizer treat enriched fields as ordinary (ignored) tokens.
    text = data.replace(b"\x1d", b" ").decode("utf-8", "replace")
    for line in text.splitlines():
        m = HEADER.match(line)
        if not m:
            continue
        rtype, ts, serial, rest = m.group(1), float(m.group(2)), int(m.group(3)), m.group(4)
        if serial not in groups:
            groups[serial] = {"serial": serial, "ts": ts, "records": [], "raw": []}
            order.append(serial)
        g = groups[serial]
        g["raw"].append(line)
        g["ts"] = min(g["ts"], ts)
        g["records"].append((rtype, rest))
    for serial in order:
        yield _build(groups[serial])


def _build(g):
    ev = {"audit_id": g["serial"], "ts": g["ts"], "raw": "\n".join(g["raw"]),
          "types": set(), "cmdline": None, "cwd": None, "saddr": None,
          "paths": [], "proctitle": None}
    for rtype, rest in g["records"]:
        ev["types"].add(rtype)
        f = _tokenize(rest)
        if rtype == "SYSCALL":
            arch = ARCH_NAME.get(f.get("arch"), f.get("arch"))
            num = int(f["syscall"]) if f.get("syscall", "").isdigit() else None
            ev["syscall"] = f.get("SYSCALL") or SYSCALL_NUM.get(arch, {}).get(num, str(num))
            ev["pid"] = _int(f.get("pid"))
            ev["ppid"] = _int(f.get("ppid"))
            ev["uid"] = _int(f.get("uid"))
            ev["gid"] = _int(f.get("gid"))
            ev["euid"] = _int(f.get("euid"))
            au = _int(f.get("auid"))
            ev["auid"] = None if au == UNSET else au
            ev["ses"] = None if f.get("ses") == str(UNSET) else f.get("ses")
            ev["tty"] = _decode_value(f.get("tty"))
            ev["comm"] = _decode_value(f.get("comm"))
            ev["exe"] = _decode_value(f.get("exe"))
            ev["audit_key"] = _decode_value(f.get("key"))
            ev["success"] = 1 if f.get("success") == "yes" else 0
            ev["exit_code"] = _int(f.get("exit"))
        elif rtype == "EXECVE":
            ev["cmdline"] = _execve_cmdline(rest)
        elif rtype == "CWD":
            ev["cwd"] = _decode_value(f.get("cwd"))
        elif rtype == "PATH":
            ev["paths"].append({"name": _decode_value(f.get("name")),
                                "nametype": f.get("nametype"),
                                "item": _int(f.get("item"))})
        elif rtype == "SOCKADDR":
            ev["saddr"] = f.get("saddr")
        elif rtype == "PROCTITLE":
            ev["proctitle"] = _decode_value(f.get("proctitle"))
    return ev


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def decode_saddr(saddr):
    """Decode an auditd saddr hex blob to (ip, port). Only AF_INET/AF_INET6."""
    if not saddr or len(saddr) < 4:
        return None, None
    try:
        b = bytes.fromhex(saddr)
    except ValueError:
        return None, None
    fam = int.from_bytes(b[0:2], "little")
    if fam == 2 and len(b) >= 8:  # AF_INET
        port = int.from_bytes(b[2:4], "big")
        ip = ".".join(str(x) for x in b[4:8])
        return ip, port
    if fam == 10 and len(b) >= 24:  # AF_INET6
        port = int.from_bytes(b[2:4], "big")
        seg = b[8:24]
        ip = ":".join(f"{int.from_bytes(seg[i:i+2],'big'):x}" for i in range(0, 16, 2))
        return ip, port
    return None, None

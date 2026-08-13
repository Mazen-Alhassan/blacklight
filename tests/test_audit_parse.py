"""Parser tests. No Docker needed: raw audit lines are fed in directly."""
import os
import tempfile

from harness.audit_parse import parse_log, decode_saddr


def _write(lines):
    fd, path = tempfile.mkstemp(suffix=".log")
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def test_execve_quoted_and_hex_args():
    # The enriched suffix after 0x1d must not corrupt the raw fields.
    lines = [
        'type=SYSCALL msg=audit(100.100:5): arch=c000003e syscall=59 success=yes '
        'exit=0 ppid=1000 pid=1002 auid=4294967295 uid=1000 gid=1000 euid=1000 '
        'ses=1 tty=(none) comm="echo" exe="/usr/bin/echo" key="lab_exec"\x1dARCH=x86_64 UID="admin"',
        'type=EXECVE msg=audit(100.100:5): argc=2 a0="/bin/echo" '
        'a1=617267207769746820737061636573',
        'type=CWD msg=audit(100.100:5): cwd="/home/admin"',
    ]
    ev = list(parse_log(_write(lines)))[0]
    assert ev["syscall"] == "execve"
    assert ev["exe"] == "/usr/bin/echo"
    assert ev["comm"] == "echo"
    assert ev["cmdline"] == "/bin/echo arg with spaces"  # hex arg decoded
    assert ev["cwd"] == "/home/admin"
    assert ev["uid"] == 1000
    assert ev["auid"] is None  # 4294967295 -> unset
    assert ev["audit_key"] == "lab_exec"


def test_saddr_ipv4():
    # AF_INET, port 8080 (0x1f90), 192.168.1.1
    saddr = "0200" + "1f90" + "c0a80101" + "0000000000000000"
    ip, port = decode_saddr(saddr)
    assert ip == "192.168.1.1"
    assert port == 8080


def test_saddr_non_inet_is_none():
    ip, port = decode_saddr("0100" + "2f746d70")  # AF_LOCAL
    assert ip is None and port is None


def test_grouping_by_serial():
    lines = [
        'type=SYSCALL msg=audit(1.0:7): arch=c000003e syscall=42 success=yes exit=0 '
        'ppid=1 pid=2 uid=0 comm="curl" exe="/usr/bin/curl" key="lab_net"',
        'type=SOCKADDR msg=audit(1.0:7): saddr=02001f90c0a80101',
    ]
    ev = list(parse_log(_write(lines)))[0]
    assert ev["syscall"] == "connect"
    assert ev["saddr"] == "02001f90c0a80101"

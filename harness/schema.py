"""The database schema. This is the contract from docs/ARCHITECTURE.md, in code.

Nothing in this project is allowed to add a column that auditd does not carry.
If a value is not in the kernel record, its column is NULL.
"""

EVENTS_DDL = """
CREATE TABLE IF NOT EXISTS events (
  id             INTEGER PRIMARY KEY,
  ts             REAL    NOT NULL,
  audit_id       INTEGER NOT NULL,
  category       TEXT    NOT NULL,
  syscall        TEXT,
  pid            INTEGER,
  ppid           INTEGER,
  comm           TEXT,
  exe            TEXT,
  cmdline        TEXT,
  cwd            TEXT,
  tty            TEXT,
  uid            INTEGER,
  gid            INTEGER,
  euid           INTEGER,
  auid           INTEGER,
  username       TEXT,
  ses            TEXT,
  parent_exe     TEXT,
  parent_cmdline TEXT,
  parent_comm    TEXT,
  success        INTEGER,
  exit_code      INTEGER,
  audit_key      TEXT,
  path           TEXT,
  path_nametype  TEXT,
  dest_ip        TEXT,
  dest_port      INTEGER,
  module_name    TEXT,
  target_pid     INTEGER,
  session_id     TEXT NOT NULL,
  window_id      TEXT,
  in_lab         INTEGER NOT NULL,
  raw            TEXT NOT NULL
);
"""

WINDOWS_DDL = """
CREATE TABLE IF NOT EXISTS windows (
  window_id   TEXT PRIMARY KEY,
  session_id  TEXT NOT NULL,
  kind        TEXT NOT NULL,
  name        TEXT NOT NULL,
  technique   TEXT,
  variant     TEXT,
  ts_start    REAL NOT NULL,
  ts_end      REAL NOT NULL,
  root_pid    INTEGER,
  exit_code   INTEGER,
  ok          INTEGER NOT NULL
);
"""

INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_events_window ON events(window_id);",
    "CREATE INDEX IF NOT EXISTS idx_events_cat ON events(category);",
    "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);",
    "CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid);",
]

# The column list the normalizer inserts, in order. Kept beside the DDL so the two
# can never drift.
EVENT_COLUMNS = [
    "ts", "audit_id", "category", "syscall",
    "pid", "ppid", "comm", "exe", "cmdline", "cwd", "tty",
    "uid", "gid", "euid", "auid", "username", "ses",
    "parent_exe", "parent_cmdline", "parent_comm",
    "success", "exit_code", "audit_key",
    "path", "path_nametype", "dest_ip", "dest_port",
    "module_name", "target_pid",
    "session_id", "window_id", "in_lab", "raw",
]

WINDOW_COLUMNS = [
    "window_id", "session_id", "kind", "name", "technique", "variant",
    "ts_start", "ts_end", "root_pid", "exit_code", "ok",
]


def init_db(conn):
    conn.execute(EVENTS_DDL)
    conn.execute(WINDOWS_DDL)
    for idx in INDEXES:
        conn.execute(idx)
    conn.commit()

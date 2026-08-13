"""The single source of truth for what telemetry the lab carries.

A Sigma field maps to a column here or it does not. If it does not, the rule that
uses it is `broken`, and the report names the field. That mapping is the honest
description of the sensor, so it lives in one place.
"""

# Sigma field name (lowercased) -> events column.
FIELD_MAP = {
    # process
    "image": "exe",
    "process.executable": "exe",
    "originalfilename": "exe",
    "commandline": "cmdline",
    "process.command_line": "cmdline",
    "parentimage": "parent_exe",
    "process.parent.executable": "parent_exe",
    "parentcommandline": "parent_cmdline",
    "process.parent.command_line": "parent_cmdline",
    "parentcomm": "parent_comm",
    "user": "username",
    "user.name": "username",
    "currentdirectory": "cwd",
    "process.working_directory": "cwd",
    "processid": "pid",
    "process.pid": "pid",
    "parentprocessid": "ppid",
    "process.parent.pid": "ppid",
    "tty": "tty",
    # auditd native names, so rules can be written directly against the telemetry
    "exe": "exe",
    "comm": "comm",
    "cmdline": "cmdline",
    "syscall": "syscall",
    "key": "audit_key",
    "auid": "auid",
    "uid": "uid",
    "euid": "euid",
    "cwd": "cwd",
    # file
    "targetfilename": "path",
    "file.path": "path",
    "path": "path",
    # network
    "destinationip": "dest_ip",
    "dst_ip": "dest_ip",
    "destination.ip": "dest_ip",
    "destinationport": "dest_port",
    "dst_port": "dest_port",
    "destination.port": "dest_port",
    # module
    "imageloaded": "module_name",
    "modulename": "module_name",
    # process access (ptrace)
    "targetprocessid": "target_pid",
    "sourceimage": "exe",
    "targetimage": "parent_exe",
}

# Columns that exist in the schema but are always NULL in this lab. A rule whose
# only selective fields are always-null is `unfirable`, not `broken`: the field
# is mapped and real, it just never carries a value here. Kept empty by default
# and filled from the actual run by the availability check.
KNOWN_NULL_COLUMNS = set()

# logsource category -> event category filter applied to every query.
LOGSOURCE_CATEGORY = {
    "process_creation": "process_creation",
    "network_connection": "network_connection",
    "file_event": "file_event",
    "file_access": "file_event",
    "file_change": "file_event",
    "process_access": "process_access",
    "driver_load": "module_load",
    "kernel_module": "module_load",
}


def map_field(field):
    """Return the column for a Sigma field, or None if unmapped."""
    if field is None:
        return "cmdline"  # bare keyword search scans the command line
    return FIELD_MAP.get(field.lower())

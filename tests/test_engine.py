"""Engine tests: field mapping decides broken vs buildable."""
import os
import tempfile

from engine.engine import compile_rule


def _rule(text):
    fd, path = tempfile.mkstemp(suffix=".yml")
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    return path


GOOD = """
title: Good linux rule
id: 00000000-0000-0000-0000-0000000000aa
tags: [attack.t1059.004, attack.execution]
logsource: {product: linux, category: process_creation}
detection:
  sel:
    Image|endswith: /bash
    CommandLine|contains: '-c'
  condition: sel
level: medium
"""

BROKEN = """
title: Windows sysmon rule
id: 00000000-0000-0000-0000-0000000000bb
tags: [attack.t1055]
logsource: {product: windows, category: process_creation}
detection:
  sel:
    Image|endswith: '\\\\rundll32.exe'
    Hashes|contains: 'MD5='
    IntegrityLevel: System
  condition: sel
level: high
"""


def test_good_rule_buildable():
    cr = compile_rule(_rule(GOOD))
    assert cr.buildable is True
    assert cr.unmapped_fields == []
    assert cr.attack == ["T1059.004"]
    assert cr.tactics == ["TA0002"]
    assert cr.category == "process_creation"
    assert "exe LIKE" in cr.where_sql and "cmdline LIKE" in cr.where_sql


def test_broken_rule_names_missing_fields():
    cr = compile_rule(_rule(BROKEN))
    assert cr.buildable is False
    assert "Hashes" in cr.unmapped_fields
    assert "IntegrityLevel" in cr.unmapped_fields
    # Image maps fine, so it must not be reported as missing.
    assert "Image" not in cr.unmapped_fields
    assert cr.where_sql is None


def test_keyword_only_rule_scans_cmdline():
    cr = compile_rule(_rule("""
title: keyword rule
id: 00000000-0000-0000-0000-0000000000cc
tags: [attack.t1105]
logsource: {product: linux, category: process_creation}
detection:
  keywords:
    - 'curl'
    - 'wget'
  condition: keywords
level: low
"""))
    assert cr.buildable is True
    assert cr.unmapped_fields == []
    assert "cmdline LIKE" in cr.where_sql

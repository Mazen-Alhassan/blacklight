"""Compile a Sigma rule into a SQL WHERE clause over the events table.

The engine decides one thing the rest of the project depends on: is this rule
even expressible against the telemetry the lab carries. It answers that before
running anything, by checking every field the rule references against the mapping
in pipeline.py. A rule that names a field the lab does not carry is `broken`, and
no query is built for it.
"""
from dataclasses import dataclass, field as dc_field
from typing import List, Optional

import yaml
from sigma.collection import SigmaCollection
from sigma.rule import SigmaDetection, SigmaDetectionItem
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation
from sigma.backends.sqlite import sqliteBackend

from engine.pipeline import map_field, LOGSOURCE_CATEGORY


def _keywords_to_cmdline(doc):
    """Rewrite value-only (keyword / full text) detections to cmdline substring
    matches. The sqlite backend cannot express an unbound search, and in this
    telemetry a keyword realistically means "appears in the command line", so the
    rewrite is both necessary and honest. It is recorded as a narrowing in the
    findings.
    """
    det = doc.get("detection")
    if not isinstance(det, dict):
        return doc
    for name, block in list(det.items()):
        if name == "condition":
            continue
        if isinstance(block, str) or isinstance(block, (int, float)):
            det[name] = {"cmdline|contains": block}
        elif isinstance(block, list) and block and all(
            isinstance(x, (str, int, float)) for x in block
        ):
            det[name] = {"cmdline|contains": block}
    return doc


@dataclass
class CompiledRule:
    id: str
    title: str
    file: str
    attack: List[str]
    tactics: List[str]
    level: str
    logsource: str
    category: Optional[str]
    fields: List[str]
    unmapped_fields: List[str] = dc_field(default_factory=list)
    where_sql: Optional[str] = None
    buildable: bool = False
    error: Optional[str] = None


def _walk_fields(det):
    out = set()
    for item in det.detection_items:
        if isinstance(item, SigmaDetection):
            out |= _walk_fields(item)
        elif isinstance(item, SigmaDetectionItem):
            out.add(item.field)  # None means a bare keyword
    return out


def rule_fields(rule):
    out = set()
    for det in rule.detection.detections.values():
        out |= _walk_fields(det)
    return out


def _attack_tags(rule):
    techniques, tactics = [], []
    tactic_names = {
        "initial_access": "TA0001", "execution": "TA0002", "persistence": "TA0003",
        "privilege_escalation": "TA0004", "defense_evasion": "TA0005",
        "credential_access": "TA0006", "discovery": "TA0007", "lateral_movement": "TA0008",
        "collection": "TA0009", "command_and_control": "TA0011", "exfiltration": "TA0010",
        "impact": "TA0040",
    }
    for t in rule.tags:
        s = str(t)
        if s.startswith("attack.t"):
            techniques.append(s.split(".", 1)[1].upper())
        elif s.startswith("attack."):
            key = s.split(".", 1)[1]
            if key in tactic_names:
                tactics.append(tactic_names[key])
    return techniques, tactics


def compile_rule(path):
    with open(path) as fh:
        text = fh.read()
    doc = yaml.safe_load(text)
    doc = _keywords_to_cmdline(doc)
    text = yaml.safe_dump(doc, sort_keys=False)
    coll = SigmaCollection.from_yaml(text)
    rule = coll.rules[0]
    techniques, tactics = _attack_tags(rule)
    ls = rule.logsource
    ls_str = "/".join(x for x in [ls.product, ls.category, ls.service] if x)
    category = LOGSOURCE_CATEGORY.get(ls.category)

    fields = rule_fields(rule)
    named = sorted(f for f in fields if f is not None)
    cr = CompiledRule(
        id=path.split("/")[-1].rsplit(".", 1)[0],
        title=rule.title or "",
        file=path,
        attack=techniques,
        tactics=sorted(set(tactics)),
        level=str(rule.level).lower() if rule.level else "medium",
        logsource=ls_str,
        category=category,
        fields=named,
    )

    # Field availability. This is the whole point.
    field_to_col = {}
    for f in fields:
        col = map_field(f)
        if f is not None and col is None:
            cr.unmapped_fields.append(f)
        elif f is not None:
            field_to_col[f] = col
    if cr.unmapped_fields:
        cr.unmapped_fields = sorted(set(cr.unmapped_fields))
        return cr  # broken: do not build a query

    # Build the WHERE clause with fields renamed to columns.
    try:
        pipeline = ProcessingPipeline([
            ProcessingItem(FieldMappingTransformation(field_to_col))
        ])
        backend = sqliteBackend(processing_pipeline=pipeline)
        queries = backend.convert(coll)
        q = queries[0]
        cr.where_sql = q.split(" WHERE ", 1)[1] if " WHERE " in q else "1=1"
        cr.buildable = True
    except Exception as exc:  # conversion failure is itself a finding
        cr.error = f"{type(exc).__name__}: {exc}"
        cr.buildable = False
    return cr

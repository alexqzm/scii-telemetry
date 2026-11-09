"""Проверки tools.check без загрузки ATT&CK: поля и значения по схеме, тактики и техники, источники."""

import json

from sigma.collection import SigmaCollection

from sciitel.schema import SCHEMA
from tools.check import check_fields, check_source, check_tactics, schema_fields
from tools.common import rule_files

FIELDS = schema_fields(json.loads(SCHEMA.read_text(encoding="utf-8")))

RULE = """
title: Test
id: 00000000-0000-4000-8000-000000000000
status: test
logsource:
    product: scii
    service: device
detection:
    selection:
        event.action: device-reject
        event.reason: {reason}
        {extra}
    condition: selection
level: low
tags:
{tags}
"""


def _rule(reason="ROLLBACK", extra="", tags="    - attack.persistence\n    - attack.t1693.001"):
    return SigmaCollection.from_yaml(RULE.format(reason=reason, extra=extra, tags=tags)).rules[0]


def test_repository_rules_pass():
    for rf in rule_files():
        for rule in rf.collection.rules:
            assert check_fields(rule, FIELDS) == [] and check_source(rule) == [], rf.key


def test_reason_enum_combines_gate_and_device_branches():
    assert {"ROLLBACK", "STATE", "DENIED", "admit", "reject"} <= FIELDS["event.reason"]
    assert FIELDS["scii.gate.code"] == {0, 10, 20, 30}
    assert FIELDS["scii.device.installed.sha256"] is None


def test_typo_in_reason_is_reported():
    assert check_fields(_rule(reason="ROLLBAKC"), FIELDS) == [
        "event.reason: значения 'ROLLBAKC' нет среди допустимых схемой"]


def test_unknown_field_is_reported():
    problems = check_fields(_rule(extra="scii.device.route: ews"), FIELDS)
    assert problems == ["поля scii.device.route нет в схеме событий"]


def test_wildcards_are_not_checked_against_enum():
    assert check_fields(_rule(reason="'ROLL*'"), FIELDS) == []


MAPPING = {"t1693.001": {"persistence", "inhibit-response-function", "impair-process-control"},
           "t1110": {"credential-access"}}


def test_tactics_consistent():
    assert check_tactics(_rule(), MAPPING) == []


def test_technique_without_matching_tactic():
    rule = _rule(tags="    - attack.credential-access\n    - attack.t1693.001")
    problems = check_tactics(rule, MAPPING)
    assert any("техника T1693.001" in p for p in problems)
    assert any("тактика credential-access" in p for p in problems)


def test_foreign_logsource():
    text = RULE.format(reason="ROLLBACK", extra="", tags="    - attack.t1110").replace("service: device", "service: audit")
    assert check_source(SigmaCollection.from_yaml(text).rules[0])

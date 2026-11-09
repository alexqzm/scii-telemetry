"""Семантика стенда: условия через SQL бэкенда SQLite, корреляции по спецификации Sigma."""

import copy

import pytest
from sigma.collection import SigmaCollection

from tools.common import dataset_events, rule_files
from tools.harness import Harness, rule_sql


def _rf(key):
    return next(rf for rf in rule_files() if rf.key == key)


def _event(event_id, ts, **fields):
    """Событие из шаблона: отказ устройства в канале управления, поля через точку заменяются."""
    base = next(e for e in dataset_events("cases") if e["event"]["action"] == "device-mgmt"
                and e["event"]["reason"] == "DENIED")
    ev = copy.deepcopy(base)
    ev["@timestamp"] = ts
    ev["event"]["id"] = event_id
    for dotted, value in fields.items():
        node = ev
        *path, last = dotted.split("__")
        for part in path:
            node = node.setdefault(part, {})
        node[last] = value
    return ev


def _gate(event_id, ts, sha, code=30):
    ev = copy.deepcopy(next(e for e in dataset_events("cpslab") if e["event"]["action"] == "gate-decision"))
    ev["@timestamp"], ev["event"]["id"] = ts, event_id
    ev["file"]["hash"]["sha256"] = sha
    ev["scii"]["gate"]["code"] = code
    return ev


def _install(event_id, ts, sha, host="plc-X"):
    ev = copy.deepcopy(next(e for e in dataset_events("cpslab") if e["event"]["action"] == "device-install"))
    ev["@timestamp"], ev["event"]["id"] = ts, event_id
    ev["file"]["hash"]["sha256"] = sha
    ev["host"]["name"] = host
    return ev


SHA_A, SHA_B = "a" * 64, "b" * 64


def _fired(events, key):
    h = Harness(events)
    return {events[i]["event"]["id"] for hits in h.correlate(_rf(key).correlation).values() for i in hits}


def test_pipeline_condition_in_sql():
    sql = rule_sql(_rf("scii_gate_veto").base_rules[0])
    assert "`event.dataset`='scii.gate'" in sql
    assert rule_sql(_rf("scii_gate_veto").base_rules[0]) == sql  # повторная конвертация не меняет правило


def test_dataset_condition_separates_sources():
    """Отказ с кодом гейта в событии гейта не находится правилом устройства."""
    ev = _event("x-1", "2026-11-09T12:00:00Z", event__reason="ROLLBACK", event__action="device-reject")
    ev["event"]["dataset"] = "scii.gate"
    h = Harness([ev])
    assert h.match(_rf("scii_device_rollback_blocked").base_rules[0]) == []


def test_strings_case_insensitive_as_in_sigma():
    ev = _event("x-1", "2026-11-09T12:00:00Z", event__reason="rollback", event__action="DEVICE-REJECT")
    assert Harness([ev]).match(_rf("scii_device_rollback_blocked").base_rules[0]) == [0]


def test_temporal_ordered_requires_order_and_window():
    events = [
        _gate("g1", "2026-11-01T00:00:00Z", SHA_A),
        _install("i1", "2026-11-20T00:00:00Z", SHA_A),            # через 19 суток — срабатывает
        _install("i2", "2026-10-31T00:00:00Z", SHA_B),            # установка раньше отказа
        _gate("g2", "2026-11-01T00:00:00Z", SHA_B),
        _gate("g3", "2026-09-01T00:00:00Z", "c" * 64),
        _install("i3", "2026-10-02T00:00:01Z", "c" * 64),         # 31 сутки — вне окна 30d
        _gate("g4", "2026-11-01T00:00:00Z", "d" * 64, code=0),    # допуск, а не отказ
        _install("i4", "2026-11-02T00:00:00Z", "d" * 64),
    ]
    assert _fired(events, "scii_rejected_release_installed") == {"i1"}


def test_temporal_ordered_fires_on_every_install_after_rejection():
    events = [_gate("g1", "2026-11-01T00:00:00Z", SHA_A)]
    events += [_install(f"i{n}", f"2026-11-0{n + 1}T00:00:00Z", SHA_A, host=f"plc-{n}") for n in range(1, 4)]
    assert _fired(events, "scii_rejected_release_installed") == {"i1", "i2", "i3"}


def test_event_count_sliding_window():
    host = {"host__name": "plc-Y"}
    within = [_event(f"d{n}", ts, **host) for n, ts in enumerate(
        ("2026-11-09T11:58:30Z", "2026-11-09T12:01:00Z", "2026-11-09T12:03:00Z"))]
    assert _fired(within, "scii_device_management_auth_failures") == {"d2"}
    spread = [_event(f"d{n}", ts, **host) for n, ts in enumerate(
        ("2026-11-09T11:30:00Z", "2026-11-09T11:40:30Z", "2026-11-09T11:51:00Z"))]
    assert _fired(spread, "scii_device_management_auth_failures") == set()


def test_event_count_groups_by_host():
    events = [_event(f"d{n}", f"2026-11-09T12:0{n}:00Z", host__name=f"plc-{n % 2}") for n in range(4)]
    assert _fired(events, "scii_device_management_auth_failures") == set()
    events.append(_event("d4", "2026-11-09T12:05:00Z", host__name="plc-0"))
    assert _fired(events, "scii_device_management_auth_failures") == {"d4"}


def test_event_count_threshold_counts_only_denied():
    events = [_event(f"d{n}", f"2026-11-09T12:0{n}:00Z", host__name="plc-Z") for n in range(2)]
    events.append(_event("ok", "2026-11-09T12:03:00Z", host__name="plc-Z", event__reason="OK",
                         event__outcome="success"))
    assert _fired(events, "scii_device_management_auth_failures") == set()


@pytest.mark.parametrize("condition, count, fires", [("gte", 3, True), ("gt", 3, False), ("eq", 3, True),
                                                      ("lt", 2, True)])
def test_event_count_operators(condition, count, fires):
    text = _rf("scii_device_management_auth_failures").path.read_text(encoding="utf-8")
    text = text.replace("        gte: 3", f"        {condition}: {count}")
    collection = SigmaCollection.from_yaml(text)
    collection.resolve_rule_references()
    corr = next(r for r in collection.rules if hasattr(r, "group_by"))
    events = [_event(f"d{n}", f"2026-11-09T12:0{n}:00Z", host__name="plc-Q") for n in range(3)]
    fired = {i for hits in Harness(events).correlate(corr).values() for i in hits}
    assert bool(fired) == fires

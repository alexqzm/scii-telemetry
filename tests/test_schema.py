"""Схема событий: наборы ей соответствуют, нарушения она ловит, шаблон индекса совпадает с ней."""

import copy
import json

import pytest

from sciitel.schema import SCHEMA, index_template, validate
from tools.common import DATASETS, ROOT, SYNTHETIC, dataset_events, load_jsonl, strip_test


@pytest.mark.parametrize("name", sorted(DATASETS))
def test_datasets_valid(name):
    events = dataset_events(name)
    assert events
    assert validate(events) == []


def test_synthetic_valid_and_described():
    events = load_jsonl(SYNTHETIC)
    assert validate([strip_test(e) for e in events]) == []
    for ev in events:
        assert ev["_test"]["case"].startswith("Синтетическ")
        assert ev["event"]["id"].startswith("synthetic-")


def test_event_ids_unique():
    for name in DATASETS:
        ids = [e["event"]["id"] for e in dataset_events(name)]
        assert len(ids) == len(set(ids)), name


def _device_event():
    return copy.deepcopy(next(e for e in dataset_events("cpslab") if e["event"]["action"] == "device-reject"))


def _gate_decision():
    return copy.deepcopy(next(e for e in dataset_events("cpslab") if e["event"]["action"] == "gate-decision"))


@pytest.mark.parametrize("mutate, where", [
    (lambda e: e["event"].update(reason="DIGSET"), "event/reason"),
    (lambda e: e["event"].update(action="device-update"), "event/action"),
    (lambda e: e["scii"]["device"].update(path="usb"), "scii/device/path"),
    (lambda e: e["scii"]["report"].update(signature="unknown"), "scii/report/signature"),
    (lambda e: e["scii"]["device"]["installed"].update(sha256="ABC"), "scii/device/installed/sha256"),
    (lambda e: e.update(extra=1), "(корень)"),
    (lambda e: e["event"].pop("sequence"), "event"),
    (lambda e: e.pop("host"), "(корень)"),
])
def test_schema_rejects_device_event(mutate, where):
    ev = _device_event()
    mutate(ev)
    problems = validate([ev])
    assert problems and any(f": {where}:" in p for p in problems), problems


@pytest.mark.parametrize("mutate", [
    lambda e: e["scii"]["gate"].update(code=40),
    lambda e: e["event"].update(reason="DIGEST"),  # причина устройства в решении гейта
    lambda e: e["scii"]["gate"].pop("veto"),
    lambda e: e["scii"]["gate"].update(r_min=1.5),
    lambda e: e.update({"@timestamp": "2026-11-09 11:38:38"}),
])
def test_schema_rejects_gate_decision(mutate):
    ev = _gate_decision()
    mutate(ev)
    assert validate([ev])


def test_index_template_matches_schema():
    committed = json.loads((ROOT / "schema" / "index-template.json").read_text(encoding="utf-8"))
    assert committed == index_template()


def test_index_template_covers_every_schema_field():
    """Каждое поле схемы (кроме меток) явно сопоставлено: dynamic: strict не отвергнет событие набора."""
    from tools.check import schema_fields

    fields = schema_fields(json.loads(SCHEMA.read_text(encoding="utf-8")))
    props = index_template()["template"]["mappings"]["properties"]

    def has(path):
        node = {"properties": props}
        for part in path.split("."):
            node = node.get("properties", {}).get(part)
            if node is None:
                return False
        return "type" in node

    missing = [f for f in fields if not f.startswith("labels") and not has(f)]
    assert missing == []

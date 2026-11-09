"""Мутационная проверка: каждое значение в условиях правил что-то решает на наборах.

Для каждого правила по очереди портится одно значение условия (строка — суффиксом, число —
сдвигом, логическое — отрицанием), и стенд пересчитывает срабатывания на наборах и синтетике.
Если порча значения ничего не меняет, это значение наборами не проверено: тест падает.
"""

import copy

import pytest
import yaml
from sigma.collection import SigmaCollection

from tools.common import DATASETS, SYNTHETIC, dataset_events, load_jsonl, rule_files
from tools.harness import Harness

SETS = {name: dataset_events(name) for name in DATASETS} | {"synthetic": load_jsonl(SYNTHETIC)}
HARNESS = {name: Harness(events) for name, events in SETS.items()}


def _fired(text: str) -> dict:
    collection = SigmaCollection.from_yaml(text)
    collection.resolve_rule_references()
    corr = next((r for r in collection.rules if hasattr(r, "group_by")), None)
    out = {}
    for name, h in HARNESS.items():
        if corr is not None:
            out[name] = {i for hits in h.correlate(corr).values() for i in hits}
        else:
            out[name] = set(h.match(collection.rules[0]))
    return out


def _spoil(value):
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    return f"{value}-mutated"


def mutations():
    for rf in rule_files():
        docs = list(yaml.safe_load_all(rf.path.read_text(encoding="utf-8")))
        for d, doc in enumerate(docs):
            for sel_name, sel in (doc.get("detection") or {}).items():
                if sel_name == "condition":
                    continue
                for field, value in sel.items():
                    values = value if isinstance(value, list) else [value]
                    for v, item in enumerate(values):
                        yield pytest.param(rf, d, sel_name, field, v, id=f"{rf.key}:{field}={item}")


@pytest.mark.parametrize("rf, doc, sel, field, index", list(mutations()))
def test_every_condition_value_matters(rf, doc, sel, field, index):
    text = rf.path.read_text(encoding="utf-8")
    docs = list(yaml.safe_load_all(text))
    mutated = copy.deepcopy(docs)
    value = mutated[doc]["detection"][sel][field]
    if isinstance(value, list):
        value[index] = _spoil(value[index])
    else:
        mutated[doc]["detection"][sel][field] = _spoil(value)
    original = _fired(text)
    spoiled = _fired(yaml.safe_dump_all(mutated, allow_unicode=True, sort_keys=False))
    assert spoiled != original, "значение не проверяется наборами: порча ничего не изменила"

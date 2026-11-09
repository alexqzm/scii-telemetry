"""Матрица обнаружения: на каких событиях наборов срабатывает каждое правило.

Правила исполняются стендом tools.harness (SQLite с конвейером полей репозитория; корреляции — по
спецификации Sigma) на наборах dataset/*/events.jsonl и на синтетических событиях
tests/events/synthetic.jsonl. Срабатывание на событии устройства записывается прогоном стенда
(labels.cpslab_run), на событии гейта — выпуском (scii.gate.variant), на синтетическом событии —
его event.id.

  python -m tools.matrix --write   # tests/expected_matrix.yml, docs/matrix.md, docs/rules.md, блоки README.md
  python -m tools.matrix --check   # всё перечисленное совпадает с правилами и наборами
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from functools import lru_cache

import yaml

from .common import (DATASETS, EXPECTED, ROOT, SYNTHETIC, RuleFile, dataset_events, get, load_jsonl,
                     load_mappings, rule_files)
from .harness import Harness

DOC_MATRIX = ROOT / "docs" / "matrix.md"
DOC_RULES = ROOT / "docs" / "rules.md"
README = ROOT / "README.md"
LEVEL_RU = {"informational": "информационный", "low": "низкий", "medium": "средний", "high": "высокий",
            "critical": "критический"}
DECISION_RU = {0: "допуск", 10: "ручное рассмотрение", 20: "запрос свидетельств", 30: "отказ"}
LEVEL_TITLES = ("L0: без проверки", "L1: подпись поставщика", "L2: квитанция гейта SCII")


# ---------------- вычисление ----------------
def fired(h: Harness, rf: RuleFile) -> set[int]:
    """Номера событий, на которых срабатывает правило файла (для корреляции — завершающие)."""
    if rf.correlation:
        return {e for hits in h.correlate(rf.correlation).values() for e in hits}
    return set(h.match(rf.base_rules[0]))


def where(event: dict) -> str:
    if event["event"]["dataset"] == "scii.gate":
        return event["scii"]["gate"]["variant"]
    return (event.get("labels") or {}).get("cpslab_run") or event["event"]["id"]


@lru_cache(maxsize=1)
def scenarios() -> list[dict]:
    return yaml.safe_load((DATASETS["cpslab"] / "raw" / "scenarios.yaml").read_text(encoding="utf-8"))["scenarios"]


@lru_cache(maxsize=1)
def cases() -> dict:
    return json.loads((DATASETS["cases"] / "raw" / "cases.json").read_text(encoding="utf-8"))


def _order(events: list[dict]):
    """Ключ сортировки мест срабатывания: выпуски по номеру решения, прогоны — по порядку сценариев."""
    rank = {s["id"]: i for i, s in enumerate(scenarios())}
    rank.update({cid: 100 + i for i, cid in enumerate(cases())})
    keys = {}
    for ev in events:
        if ev["event"]["action"] == "gate-decision":
            keys[ev["scii"]["gate"]["variant"]] = (0, ev["scii"]["gate"]["serial"], 0)
        labels = ev.get("labels") or {}
        if "cpslab_run" in labels:
            keys[labels["cpslab_run"]] = (1, rank.get(labels["cpslab_scenario"], 999), int(labels["cpslab_level"]))
    return lambda name: keys.get(name, (2, 0, 0)) + (name,)


def compute(rfs: list[RuleFile] | None = None) -> dict:
    rfs = rfs or rule_files()
    out = {}
    for name in DATASETS:
        events = dataset_events(name)
        h, key = Harness(events), _order(events)
        out[name] = {rf.key: sorted({where(events[i]) for i in fired(h, rf)}, key=key) for rf in rfs}
    synthetic = load_jsonl(SYNTHETIC)
    h = Harness(synthetic)
    out["synthetic"] = {rf.key: sorted(synthetic[i]["event"]["id"] for i in fired(h, rf)) for rf in rfs}
    return out


def expected_synthetic(rfs: list[RuleFile]) -> dict:
    """Ожидания синтетических событий из их поля _test.rules."""
    events = load_jsonl(SYNTHETIC)
    return {rf.key: sorted(e["event"]["id"] for e in events if rf.key in e["_test"]["rules"]) for rf in rfs}


# ---------------- файлы ----------------
def matrix_yaml(m: dict) -> str:
    lines = [
        "# Матрица обнаружения: сгенерирована python -m tools.matrix --write, вручную не правится.",
        "# Для каждого набора и правила — прогоны стенда (события устройств) и выпуски (события гейта),",
        "# на которых правило срабатывает; synthetic — синтетические события tests/events/synthetic.jsonl.",
        "# Пустой список: правило в наборе не срабатывает.",
    ]
    for name, rules in m.items():
        lines.append(f"{name}:")
        for key, places in rules.items():
            lines.append(f"  {key}: [{', '.join(places)}]")
    return "\n".join(lines) + "\n"


def _labels(m: dict, dataset: str, place: str, rfs: list[RuleFile], mappings: dict) -> list[str]:
    return [mappings["rules"][rf.key]["label"] for rf in rfs if place in m[dataset][rf.key]]


def _attempt(events: list[dict], run: str) -> str:
    """Исход прогона по последнему отчёту устройства после ввода в эксплуатацию."""
    evs = [e for e in events if (e.get("labels") or {}).get("cpslab_run") == run
           and e["event"]["action"] != "device-factory"]
    if not evs:
        return "нет попытки"
    ev = evs[-1]
    action, reason = ev["event"]["action"], ev["event"].get("reason")
    if action == "device-mgmt":
        cmd = get(ev, "scii.mgmt.command")
        return f"команда {cmd} выполнена" if ev["event"]["outcome"] == "success" else f"команда {cmd}: {reason}"
    return "принято" if ev["event"]["outcome"] == "success" else f"отказ {reason}"


def _cell(outcome: str, labels: list[str]) -> str:
    return f"{outcome} → {'; '.join(labels)}" if labels else f"{outcome} → —"


def _gate_info(events: list[dict]) -> dict:
    """Выпуск → номер, решение, вето, опровергнутые и непредъявленные обязательные свидетельства."""
    info = {}
    for ev in events:
        g = ev["scii"].get("gate") if ev["event"]["dataset"] == "scii.gate" else None
        if g is None:
            continue
        rec = info.setdefault(g["variant"], {"refuted": [], "missing_mandatory": []})
        if ev["event"]["action"] == "gate-decision":
            rec.update(serial=g["serial"], code=g["code"], veto=g["veto"], package=ev["package"])
        else:
            e = ev["scii"]["evidence"]
            if e["state"] == "refuted":
                rec["refuted"].append(e["id"])
            if e["state"] == "missing" and e["mandatory"]:
                rec["missing_mandatory"].append(e["id"])
    return info


def _decision(rec: dict) -> str:
    text = DECISION_RU[rec["code"]]
    return text + (", вето" if rec["veto"] else "")


def scenario_table(m: dict, rfs: list[RuleFile], mappings: dict) -> str:
    events = dataset_events("cpslab")
    gate = _gate_info(events)
    rows = [f"| Сценарий стенда | {' | '.join(LEVEL_TITLES)} | Решение гейта по выпуску |",
            "|---|---|---|---|---|"]
    for s in scenarios():
        cells = []
        for level in range(3):
            run = f"{s['id']}-L{level}"
            cells.append(_cell(_attempt(events, run), _labels(m, "cpslab", run, rfs, mappings)))
        rel = mappings["scenario_release"][s["id"]]
        gcell = _cell(_decision(gate[rel]), _labels(m, "cpslab", rel, rfs, mappings)) if rel else "не участвует"
        rows.append(f"| {s['id']} {s['title']} | {' | '.join(cells)} | {gcell} |")
    return "\n".join(rows)


def cases_table(m: dict, rfs: list[RuleFile], mappings: dict) -> str:
    events = dataset_events("cases")
    gate = _gate_info(events)
    runs = {}
    for ev in events:
        labels = ev.get("labels") or {}
        if "cpslab_run" in labels:
            runs.setdefault(labels["cpslab_scenario"], labels["cpslab_run"])
    rows = ["| Случай | Что сделано | Исход | Правила |", "|---|---|---|---|"]
    for cid, c in cases().items():
        if cid in runs:
            place = runs[cid]
            outcome = _attempt(events, place)
            if cid == "C7":
                outcome = c["outcome"]
            where_ = f"`{place}`"
        else:
            place = mappings["case_release"][cid]
            outcome = f"решение гейта: {_decision(gate[place])}"
            where_ = f"выпуск `{place}`"
        labels = _labels(m, "cases", place, rfs, mappings)
        rows.append(f"| {cid} | {c['case']} ({where_}) | {outcome} | {'; '.join(labels) or '—'} |")
    return "\n".join(rows)


def gate_table(m: dict, rfs: list[RuleFile], mappings: dict) -> str:
    events = dataset_events("cases")
    gate = _gate_info(events)
    rows = ["| № | Выпуск | Решение | Опровергнуты | Не предъявлены обязательные | Правила |",
            "|---|---|---|---|---|---|"]
    for variant, rec in sorted(gate.items(), key=lambda kv: kv[1]["serial"]):
        labels = _labels(m, "cases", variant, rfs, mappings)
        rows.append(f"| {rec['serial']} | `{variant}` | {_decision(rec)} | {', '.join(rec['refuted']) or '—'} | "
                    f"{', '.join(rec['missing_mandatory']) or '—'} | {'; '.join(labels) or '—'} |")
    return "\n".join(rows)


def _scenario_ids(places: list[str]) -> str:
    """A2-L0, A2-L1, A3-L0 → A2 (L0, L1), A3 (L0)."""
    groups: dict[str, list[str]] = {}
    for p in places:
        sid, _, level = p.rpartition("-L")
        groups.setdefault(sid, []).append(f"L{level}")
    return ", ".join(f"{sid} ({', '.join(levels)})" for sid, levels in groups.items()) or "—"


def rules_summary(m: dict, rfs: list[RuleFile], mappings: dict) -> str:
    rows = ["| Правило | Уровень | Сценарии стенда | Случаи C1–C9 | Синтетика |", "|---|---|---|---|---|"]
    for rf in rfs:
        lab = m["cpslab"][rf.key]
        if "gate" in rf.services and not rf.correlation:
            lab_text = ", ".join(f"`{v}`" for v in lab) or "—"
            cases_text = ", ".join(f"`{v}`" for v in m["cases"][rf.key] if v not in lab) or "—"
        else:
            lab_text = _scenario_ids(lab)
            cases_text = _scenario_ids(m["cases"][rf.key])
        level = LEVEL_RU[rf.primary.level.name.lower()]
        rows.append(f"| [`{rf.key}`](../{rf.rel}) — {mappings['rules'][rf.key]['label']} | {level} | {lab_text} | "
                    f"{cases_text} | {', '.join(m['synthetic'][rf.key]) or '—'} |")
    return "\n".join(rows)


def _attack(rf: RuleFile) -> str:
    tags = [t for t in rf.primary.tags if t.namespace == "attack" and re.fullmatch(r"t\d{4}(\.\d{3})?", t.name)]
    return ", ".join(t.name.upper() for t in tags)


def rules_table(rfs: list[RuleFile], mappings: dict, prefix: str) -> str:
    rows = ["| Правило | Источник | Уровень | ATT&CK | Что означает |", "|---|---|---|---|---|"]
    for rf in rfs:
        source = "корреляция" if rf.correlation else {"device": "устройство", "gate": "гейт"}[rf.base_rules[0].logsource.service]
        level = LEVEL_RU[rf.primary.level.name.lower()]
        rows.append(f"| [`{rf.key}`]({prefix}{rf.rel}) | {source} | {level} | {_attack(rf)} | "
                    f"{mappings['rules'][rf.key]['summary']} |")
    return "\n".join(rows)


def doc_matrix(m: dict, rfs: list[RuleFile], mappings: dict) -> str:
    return "\n".join([
        "# Матрица обнаружения",
        "",
        "Сгенерирована `python -m tools.matrix --write` по наборам [`dataset/`](../dataset/) и",
        "синтетическим событиям [`tests/events/synthetic.jsonl`](../tests/events/synthetic.jsonl); вручную",
        "не правится. CI проверяет, что она совпадает с правилами и наборами (`--check`). Правила",
        "исполняет стенд [`tools/harness.py`](../tools/harness.py), а запросы из [`conversions/`](../conversions/)",
        "на тех же событиях — OpenSearch и Elasticsearch ([`siem.md`](siem.md)).",
        "",
        "В ячейке — исход попытки на устройстве (по последнему отчёту прогона) и правила, сработавшие",
        "на событиях прогона; «—» — ни одно правило не сработало.",
        "",
        "## Сценарии cps-update-lab",
        "",
        "Набор `dataset/cpslab-0.1.0`: 33 прогона `cpslab scenario matrix` (11 сценариев × 3 уровня",
        "защиты) и 8 решений гейта. Описание сценариев — в",
        "[cps-update-lab](https://github.com/alexqzm/cps-update-lab).",
        "",
        scenario_table(m, rfs, mappings),
        "",
        "## Дополнительные случаи",
        "",
        "Набор `dataset/cases-0.1.0`: случаи [`labcases/cases.py`](../labcases/cases.py) на копии каталога",
        "стенда после `scenario matrix` — для правил, которых не касаются сценарии стенда. Квитанции",
        "проверяет scii-agent, отчёты подписаны ключами устройств, решение по выпуску принимает гейт стенда.",
        "",
        cases_table(m, rfs, mappings),
        "",
        "## Решения гейта",
        "",
        "Решения 1–8 входят в оба набора, решение 9 — только в `cases-0.1.0` (случай C9).",
        "",
        gate_table(m, rfs, mappings),
        "",
        "## По правилам",
        "",
        rules_summary(m, rfs, mappings),
        "",
    ])


def doc_rules(rfs: list[RuleFile], mappings: dict) -> str:
    return "\n".join([
        "# Правила",
        "",
        "Сгенерировано `python -m tools.matrix --write` из [`rules/`](../rules/) и",
        "[`mappings/mappings.yml`](../mappings/mappings.yml). Уровень и техники ATT&CK — из правил",
        "(для корреляции — из правила корреляции; базовые правила корреляций — информационные).",
        "Где правило срабатывает — в [`matrix.md`](matrix.md).",
        "",
        rules_table(rfs, mappings, "../"),
        "",
    ])


def readme_text(current: str, m: dict, rfs: list[RuleFile], mappings: dict) -> str:
    blocks = {"matrix": scenario_table(m, rfs, mappings), "rules": rules_table(rfs, mappings, "")}
    for name, body in blocks.items():
        begin, end = f"<!-- {name}:begin -->", f"<!-- {name}:end -->"
        if begin not in current or end not in current:
            raise SystemExit(f"README.md: нет меток {begin} … {end}")
        head, rest = current.split(begin, 1)
        _, tail = rest.split(end, 1)
        current = f"{head}{begin}\n{body}\n{end}{tail}"
    return current


def ordered_rule_files() -> list[RuleFile]:
    """Файлы правил в порядке mappings.yml: устройство, гейт, корреляции."""
    order = list(load_mappings()["rules"])
    return sorted(rule_files(), key=lambda rf: (order.index(rf.key) if rf.key in order else len(order), rf.key))


def outputs(m: dict, rfs: list[RuleFile]) -> dict:
    mappings = load_mappings()
    missing = {rf.key for rf in rfs} ^ set(mappings["rules"])
    if missing:
        raise SystemExit(f"mappings.yml и rules/ расходятся: {sorted(missing)}")
    files = {EXPECTED: matrix_yaml(m), DOC_MATRIX: doc_matrix(m, rfs, mappings), DOC_RULES: doc_rules(rfs, mappings)}
    if README.exists():
        files[README] = readme_text(README.read_text(encoding="utf-8"), m, rfs, mappings)
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    rfs = ordered_rule_files()
    m = compute(rfs)
    want = expected_synthetic(rfs)
    if m["synthetic"] != want:
        for key in want:
            if m["synthetic"][key] != want[key]:
                print(f"синтетика: {key} срабатывает на {m['synthetic'][key]}, ожидалось {want[key]}")
        return 1
    files = outputs(m, rfs)
    stale = [p for p, text in files.items() if not p.exists() or p.read_text(encoding="utf-8") != text]
    if args.check:
        for p in stale:
            print(f"расходится с правилами и наборами: {p.relative_to(ROOT)}")
        print(f"файлов: {len(files)}, расхождений: {len(stale)}")
        return 1 if stale else 0
    for p in stale:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(files[p], encoding="utf-8")
        print(f"записано: {p.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Набор ardupilot-0.1.0: файлы прогона scii-gate, выгрузка решений гейта и срабатывания правил.

Ожидаемые срабатывания строятся из плана испытаний (testbed/plan.json scii-gate). План вычислен
моделью по замыслу сценариев, а его SHA-256 записан в PMI.sha256 до прогона, поэтому ожидания не
зависят ни от отчётов гейта, ни от выгрузки, ни от правил. Группы сценариев — по ПМИ стенда:
O — выпуск апстрима, B — штатные выпуски поставщика, A — атаки.
"""

import hashlib
import json
import shutil

import pytest

from sciitel.export import ardupilot_entries
from tools.common import DATASETS, dataset_events, rule_files
from tools.matrix import compute, ordered_rule_files

ROOT = DATASETS["ardupilot"]
RAW = ROOT / "raw"
#: файл scii-gate → файл raw/
RUN_FILES = {"results/results.json": "results.json", "testbed/plan.json": "plan.json",
             "profiles/ardupilot_cubeorange.json": "profile.json", "docs/PMI.sha256": "PMI.sha256"}


def _json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def matrix():
    return compute(ordered_rule_files())


@pytest.fixture(scope="module")
def plan():
    return {s["id"]: s for s in _json(RAW / "plan.json")["scenarios"]}


# ---------------- файлы прогона ----------------
def test_plan_and_profile_recorded_before_run():
    """План и профиль — те, чьи SHA-256 записаны до прогона и в окружении прогона."""
    recorded = {}
    for line in (RAW / "PMI.sha256").read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            digest, path = line.split()
            recorded[path] = digest
    env = _json(RAW / "results.json")["environment"]["sha256"]
    for src, dst in (("testbed/plan.json", "plan.json"), ("profiles/ardupilot_cubeorange.json", "profile.json")):
        assert recorded[src] == env[src] == _sha256(RAW / dst)


def test_raw_files_are_scii_gate_files():
    """raw/ — файлы scii-gate на закреплённом коммите: SHA-256 из provenance.json."""
    files = _json(ROOT / "provenance.json")["testbed"]["files_sha256"]
    reports = [src for src in files if src.startswith("results/reports/")]
    assert len(reports) == 16
    for src, digest in files.items():
        dst = RUN_FILES.get(src) or "reports/" + src.rsplit("/", 1)[1]
        assert _sha256(RAW / dst) == digest, src
    assert sorted(p.name for p in (RAW / "reports").iterdir()) == sorted(r.rsplit("/", 1)[1] for r in reports)


def test_run_followed_plan(plan):
    """Официальный прогон совпал с планом: состояния 17 свидетельств и решения всех 16 сценариев."""
    entries = ardupilot_entries(RAW)
    assert [entry["variant"] for entry, _ in entries] == list(plan)
    for entry, report in entries:
        p = plan[entry["variant"]]
        assert report["states"] == p["expect_states"]
        assert report["decision"] == p["expect"]["decision"]


def test_entries_board_and_versions():
    """Класс устройства — board_id платы CubeOrange; откат A4 — подлинный выпуск 4.5.5."""
    entries = ardupilot_entries(RAW)
    assert {entry["device_class"] for entry, _ in entries} == {140}
    versions = {entry["variant"]: entry["version"] for entry, _ in entries}
    assert versions.pop("A4") == "4.5.5"
    assert set(versions.values()) == {"4.5.7"}


def test_entries_reject_files_of_different_runs(tmp_path):
    raw = tmp_path / "raw"
    shutil.copytree(RAW, raw)
    results = _json(raw / "results.json")
    results["scenarios"][2]["exit_code"] = 30
    (raw / "results.json").write_text(json.dumps(results, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(ValueError, match="B1"):
        ardupilot_entries(raw)


def test_event_ids_do_not_collide_with_lab():
    ids = [e["event"]["id"] for e in dataset_events("ardupilot")]
    assert len(set(ids)) == len(ids) == 16 * 18
    lab = {e["event"]["id"] for name in ("cpslab", "cases") for e in dataset_events(name)}
    assert not set(ids) & lab


# ---------------- правила ----------------
#: ожидание по плану: состояния свидетельств и решение, вычисленные до прогона
PLAN_ORACLE = {
    "scii_gate_veto": lambda p: p["expect"]["G"] == 0,
    "scii_gate_release_rejected": lambda p: p["expect"]["decision"] == "отказ",
    "scii_gate_evidence_requested": lambda p: p["expect"]["decision"] == "запрос свидетельств",
    "scii_gate_rebuild_mismatch": lambda p: p["expect_states"]["s24"] == "F",
    "scii_gate_source_signature_refuted": lambda p: "F" in (p["expect_states"]["s11"], p["expect_states"]["s14"]),
}


@pytest.mark.parametrize("rule", sorted(PLAN_ORACLE))
def test_gate_rules_as_planned(matrix, plan, rule):
    want = [sid for sid, p in plan.items() if PLAN_ORACLE[rule](p)]
    assert want
    assert matrix["ardupilot"][rule] == want


def test_device_and_correlation_rules_silent(matrix):
    """Устройства на стенде нет: правила по отчётам устройств и корреляции молчат."""
    gate = {rf.key for rf in rule_files() if rf.services == {"gate"} and not rf.correlation}
    assert set(PLAN_ORACLE) == gate
    assert {key: hits for key, hits in matrix["ardupilot"].items() if key not in gate and hits} == {}


def _flagged(matrix):
    out = {}
    for key, hits in matrix["ardupilot"].items():
        for sid in hits:
            out.setdefault(sid, []).append(key)
    return out


def test_attacks_flagged_except_compromised_builder_without_rebuild(matrix, plan):
    """Правила гейта отмечают 8 из 9 атак; A5b — ручное рассмотрение без опровержений — нет."""
    flagged = _flagged(matrix)
    attacks = [sid for sid in plan if sid.startswith("A")]
    assert len(attacks) == 9
    assert [sid for sid in attacks if sid not in flagged] == ["A5b"]


def test_benign_releases_alerts(matrix, plan):
    """Штатные: запросы свидетельств по выпуску апстрима и вето B5a — ложное срабатывание правила вето."""
    flagged = _flagged(matrix)
    benign = [sid for sid in plan if not sid.startswith("A")]
    assert len(benign) == 7
    assert {sid: sorted(flagged[sid]) for sid in benign if sid in flagged} == {
        "O1": ["scii_gate_evidence_requested"],
        "O2": ["scii_gate_evidence_requested"],
        "B5a": ["scii_gate_release_rejected", "scii_gate_veto"],
    }


def _decision(events, variant):
    ev = next(e for e in events if e["event"]["action"] == "gate-decision" and e["scii"]["gate"]["variant"] == variant)
    return ev


def _states(events, variant):
    return {e["scii"]["evidence"]["id"]: e["scii"]["evidence"]["state"] for e in events
            if e["event"]["action"] == "gate-evidence" and e["scii"]["gate"]["variant"] == variant}


def test_compromised_builder_without_rebuild_looks_like_b3(matrix):
    """A5b и штатный B3 не различаются ничем, кроме SHA-256 пакета: правилам гейта не на что опереться."""
    events = dataset_events("ardupilot")
    a5b, b3 = _decision(events, "A5b"), _decision(events, "B3")
    keep = ("code", "veto", "complete", "r_min", "r_max", "theta")
    assert {k: a5b["scii"]["gate"][k] for k in keep} == {k: b3["scii"]["gate"][k] for k in keep}
    assert _states(events, "A5b") == _states(events, "B3")
    assert a5b["file"]["hash"]["sha256"] != b3["file"]["hash"]["sha256"]
    assert not [key for key, hits in matrix["ardupilot"].items() if "A5b" in hits or "B3" in hits]


def test_vendor_key_change_is_the_listed_false_positive(matrix):
    """B5a и B5b — один и тот же пакет: вето при необновлённой политике, допуск при обновлённой."""
    events = dataset_events("ardupilot")
    b5a, b5b = _decision(events, "B5a"), _decision(events, "B5b")
    assert b5a["file"]["hash"]["sha256"] == b5b["file"]["hash"]["sha256"]
    assert (b5a["scii"]["gate"]["veto"], b5b["scii"]["gate"]["decision"]) == (True, "admit")
    assert "B5a" in matrix["ardupilot"]["scii_gate_veto"] and "B5b" not in matrix["ardupilot"]["scii_gate_veto"]
    veto = next(rf for rf in rule_files() if rf.key == "scii_gate_veto")
    assert any("key change" in fp for fp in veto.primary.falsepositives)

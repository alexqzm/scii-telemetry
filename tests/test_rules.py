"""Правила на наборах: матрица обнаружения и её сверка с независимыми ожиданиями.

Ожидания здесь не берутся из выгруженных событий и не используют SQL стенда: они строятся из
каталога сценариев cps-update-lab (ожидаемые исходы и тревоги монитора на каждом уровне защиты),
сырых отчётов гейта (вето, опровергнутые свидетельства) и сырых отчётов устройств. Совпадение
матрицы с ними показывает, что правило ловит ровно то, что задумано, а не просто «что-то».
"""

import json
from pathlib import Path

import pytest
import yaml

from tools.common import DATASETS, EXPECTED, load_mappings
from tools.matrix import compute, expected_synthetic, ordered_rule_files

RAW = {name: path / "raw" for name, path in DATASETS.items()}


@pytest.fixture(scope="module")
def matrix():
    return compute(ordered_rule_files())


@pytest.fixture(scope="module")
def scenarios():
    return yaml.safe_load((RAW["cpslab"] / "scenarios.yaml").read_text(encoding="utf-8"))["scenarios"]


def _runs(scenarios, pred):
    return sorted(f"{s['id']}-L{level[1:]}" for s in scenarios for level, exp in s["expected"].items()
                  if pred(s, exp))


def test_matrix_matches_committed(matrix):
    committed = yaml.safe_load(EXPECTED.read_text(encoding="utf-8"))
    assert matrix == committed


def test_synthetic_expectations(matrix):
    assert matrix["synthetic"] == expected_synthetic(ordered_rule_files())


def test_every_rule_fires_somewhere(matrix):
    silent = [key for key in matrix["cpslab"] if not any(matrix[s][key] for s in matrix)]
    assert silent == []


def test_only_state_rule_relies_on_synthetic_alone(matrix):
    synthetic_only = [key for key in matrix["cpslab"]
                      if matrix["synthetic"][key] and not matrix["cpslab"][key] and not matrix["cases"][key]]
    assert synthetic_only == ["scii_device_state_invalid"]


# ---------------- отказы устройств ↔ ожидаемые коды стенда ----------------
REASON_RULE = {
    "BOOT_SIG": "scii_device_boot_signature_rejected",
    "DIGEST": "scii_device_image_digest_mismatch",
    "ROLLBACK": "scii_device_rollback_blocked",
    "TARGET": "scii_device_wrong_target",
}


@pytest.mark.parametrize("reason", sorted(REASON_RULE))
def test_refusal_rules_match_lab_expectations(matrix, scenarios, reason):
    want = _runs(scenarios, lambda s, exp: exp["reason"] == reason)
    assert want, reason
    assert sorted(matrix["cpslab"][REASON_RULE[reason]]) == want


def test_no_receipt_split_by_path(matrix, scenarios):
    """NO_RECEIPT: загрузка логики (сценарий A6, путь ews) и канал обновления — разные правила."""
    ews = _runs(scenarios, lambda s, exp: exp["reason"] == "NO_RECEIPT" and s["id"] == "A6")
    update = _runs(scenarios, lambda s, exp: exp["reason"] == "NO_RECEIPT" and s["id"] != "A6")
    assert sorted(matrix["cpslab"]["scii_device_program_download_without_receipt"]) == ews == ["A6-L2"]
    assert sorted(matrix["cpslab"]["scii_device_update_without_receipt"]) == update


def test_not_admitted_matches_lab_monitor(matrix, scenarios):
    """Сверка с журналом гейта срабатывает там же, где тревога монитора стенда."""
    want = _runs(scenarios, lambda s, exp: exp["alert"])
    assert sorted(matrix["cpslab"]["scii_device_installed_image_not_admitted"]) == want


def _version(name):
    return tuple(int(x) for x in name.split("-")[1].split("."))


def test_version_decreased_where_monitor_is_silent(matrix, scenarios):
    """Откат на старый допущенный выпуск: монитор стенда молчит, правило версии срабатывает."""
    release = load_mappings()["scenario_release"]
    want = _runs(scenarios, lambda s, exp: exp["accepted"] and release[s["id"]]
                 and _version(release[s["id"]]) < _version(s["initial"]))
    assert want == ["A4-L0", "A4-L1"]
    assert sorted(matrix["cpslab"]["scii_device_version_decreased"]) == want
    assert not set(want) & set(matrix["cpslab"]["scii_device_installed_image_not_admitted"])


def test_management_channel(matrix, scenarios):
    m2 = _runs(scenarios, lambda s, exp: s["id"] == "M2")
    assert sorted(matrix["cpslab"]["scii_device_management_command_accepted"]) == m2
    assert matrix["cases"]["scii_device_management_command_accepted"] == ["C7-L2"]
    assert matrix["cases"]["scii_device_management_auth_failures"] == ["C7-L2"]
    assert matrix["cpslab"]["scii_device_management_auth_failures"] == []


def test_method_boundary_and_normal_update_stay_silent(matrix):
    """Штатное обновление (N1) и скрытая функция поставщика (M1) не поднимают ни одного правила."""
    fired = {run for rules in matrix["cpslab"].values() for run in rules}
    assert not [run for run in fired if run.split("-L")[0] in ("N1", "M1")]


# ---------------- корреляция: независимый пересчёт по сырым файлам ----------------
def _raw_reports(name):
    for path in sorted((RAW[name] / "runs").glob("*/device/reports.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            yield path.parent.parent.name, json.loads(line)["event"]


def _ledger(name):
    return [json.loads(x) for x in (RAW[name] / "gate" / "ledger.jsonl").read_text(encoding="utf-8").splitlines()]


@pytest.mark.parametrize("name", sorted(DATASETS))
def test_rejected_release_installed_recomputed(matrix, name):
    rejected = {e["sha256"] for e in _ledger(name) if e["code"] == 30}
    want = sorted({run for run, r in _raw_reports(name)
                   if r["event"] == "install" and r["accepted"] and r["installed_sha256"] in rejected})
    assert sorted(matrix[name]["scii_rejected_release_installed"]) == want


def test_lab_image_reuse_explains_a1_and_a6(matrix):
    """A1 (L0) и A6 (L0, L1) попадают в корреляцию: стенд использует один вредоносный образ."""
    hits = matrix["cpslab"]["scii_rejected_release_installed"]
    assert {"A1-L0", "A6-L0", "A6-L1"} <= set(hits)
    images = {r["candidate_sha256"] for run, r in _raw_reports("cpslab")
              if run in ("A1-L0", "A3-L0", "A6-L0") and r["event"] == "install"}
    assert len(images) == 1


# ---------------- гейт: сверка с сырыми отчётами scii-gate ----------------
def _gate_reports(name):
    out = {}
    for entry in _ledger(name):
        report = json.loads((RAW[name] / entry["run"] / "report.json").read_text(encoding="utf-8"))
        out[entry["variant"]] = (entry, report)
    return out


GATE_ORACLE = {
    "scii_gate_veto": lambda entry, rep: rep["G"] == 0,
    "scii_gate_release_rejected": lambda entry, rep: entry["code"] == 30,
    "scii_gate_evidence_requested": lambda entry, rep: entry["code"] == 20,
    "scii_gate_rebuild_mismatch": lambda entry, rep: rep["states"].get("s24") == "F",
    "scii_gate_source_signature_refuted": lambda entry, rep: "F" in (rep["states"].get("s11"), rep["states"].get("s14")),
}


@pytest.mark.parametrize("name", sorted(DATASETS))
@pytest.mark.parametrize("rule", sorted(GATE_ORACLE))
def test_gate_rules_match_gate_reports(matrix, name, rule):
    want = sorted(v for v, (entry, rep) in _gate_reports(name).items() if GATE_ORACLE[rule](entry, rep))
    if (name, rule) != ("cpslab", "scii_gate_evidence_requested"):  # в сценариях стенда запроса нет
        assert want
    assert sorted(matrix[name][rule]) == want


def test_gate_expectations_of_lab_catalog(matrix, scenarios):
    """Решение гейта по выпуску сценария совпадает с каталогом стенда: отказ — правило отказа."""
    release = load_mappings()["scenario_release"]
    rejected = {release[s["id"]] for s in scenarios if s["gate"] == 30}
    assert sorted(rejected) == sorted(matrix["cpslab"]["scii_gate_release_rejected"])
    vetoed = {release[s["id"]] for s in scenarios if s["gate"] == 30 and "(вето)" in s["stopped_by"]}
    assert sorted(vetoed) == sorted(matrix["cpslab"]["scii_gate_veto"])


# ---------------- дополнительные случаи ----------------
CASE_RULE = {
    "C1": "scii_device_receipt_rejected", "C2": "scii_device_receipt_rejected",
    "C3": "scii_device_receipt_rejected", "C4": "scii_device_receipt_rejected",
    "C5": "scii_device_receipt_rejected", "C6": "scii_device_image_digest_mismatch",
    "C7": "scii_device_management_auth_failures", "C8": "scii_device_report_signature_invalid",
}


def test_cases_outcomes_recorded():
    cases = json.loads((RAW["cases"] / "cases.json").read_text(encoding="utf-8"))
    assert list(cases) == [f"C{i}" for i in range(1, 10)]
    assert all(c["outcome"] == c["expected"] for c in cases.values())


@pytest.mark.parametrize("case", sorted(CASE_RULE))
def test_case_detected_by_its_rule(matrix, case):
    runs = [run for run in matrix["cases"][CASE_RULE[case]] if run.startswith(f"{case}-")]
    assert len(runs) == 1


def test_forged_report_hides_installation_from_reconciliation(matrix):
    """C8: подменённый в отчёте образ гасит сверку и корреляцию — остаётся подпись отчёта."""
    assert "C8-L0" in matrix["cases"]["scii_device_report_signature_invalid"]
    assert "C8-L0" not in matrix["cases"]["scii_device_installed_image_not_admitted"]
    assert "C8-L0" not in matrix["cases"]["scii_rejected_release_installed"]


def test_missing_provenance_requests_evidence(matrix):
    variant = load_mappings()["case_release"]["C9"]
    assert matrix["cases"]["scii_gate_evidence_requested"] == [variant]
    entry, report = _gate_reports("cases")[variant]
    assert report["states"]["s22"] == "N" and report["G"] == "⊥"


def test_rule_files_have_mappings():
    keys = {Path(rf.path).stem for rf in ordered_rule_files()}
    assert keys == set(load_mappings()["rules"])

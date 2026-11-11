"""Выгрузка: наборы воспроизводятся из сырых выходов стенда, подпись, сверка и версия считаются верно."""

import json
import shutil
import subprocess
import sys

import pytest

from sciitel.export import Profile, canonical_json, device_events, export_ardupilot, export_lab, write_jsonl
from sciitel.schema import comparable, load_events
from tools.common import DATASETS, EXPORTER, ROOT

#: стенд, из которого получен набор: раздел provenance.json и закреплённый коммит
SOURCE_COMMIT = {
    "cpslab": ("lab", "2d22f9c55e67f888969d89fce5eea36ae5f7ee5d"),
    "cases": ("lab", "2d22f9c55e67f888969d89fce5eea36ae5f7ee5d"),
    "ardupilot": ("testbed", "d210811f27a9b9302f018faf7f019d38dfbb9227"),
}


def _raw(name):
    return DATASETS[name] / "raw"


def _export(name):
    export = {"lab": export_lab, "ardupilot": export_ardupilot}[EXPORTER[name]]
    return export(_raw(name), _raw(name) / "profile.json")


@pytest.mark.parametrize("name", sorted(DATASETS))
def test_dataset_is_export_of_raw(name, tmp_path):
    """events.jsonl — побайтно выгрузка сырых выходов стенда из raw/."""
    out = tmp_path / "events.jsonl"
    write_jsonl(_export(name), out)
    assert out.read_bytes() == (DATASETS[name] / "events.jsonl").read_bytes()


@pytest.mark.parametrize("name", sorted(DATASETS))
def test_provenance_counts(name):
    prov = json.loads((DATASETS[name] / "provenance.json").read_text(encoding="utf-8"))
    events = load_events(DATASETS[name] / "events.jsonl")
    assert prov["events"] == len(events)
    by = {}
    for ev in events:
        by[ev["event"]["dataset"]] = by.get(ev["event"]["dataset"], 0) + 1
    assert prov["datasets"] == by
    section, commit = SOURCE_COMMIT[name]
    assert prov[section]["commit"] == commit


def test_compare_ignore_option(tmp_path):
    """compare --ignore: поле не сравнивается, остальные — как прежде."""
    path = DATASETS["ardupilot"] / "events.jsonl"
    events = load_events(path)
    for ev in events:
        ev["observer"]["version"] = "0.1.5"
    other = tmp_path / "other.jsonl"
    write_jsonl(events, other)
    assert _cli("compare", str(path), str(other)).returncode == 1
    assert _cli("compare", str(path), str(other), "--ignore", "observer.version").returncode == 0
    events[0]["scii"]["gate"]["code"] = 30
    write_jsonl(events, other)
    assert _cli("compare", str(path), str(other), "--ignore", "observer.version").returncode == 1


def test_profile_catalog():
    profile = Profile.load(_raw("cpslab") / "profile.json")
    assert len(profile.evidence) == 17
    mandatory = sorted(k for k, v in profile.evidence.items() if v["mandatory"])
    assert mandatory == ["s22", "s42"]


def test_all_lab_reports_verify():
    events = load_events(DATASETS["cpslab"] / "events.jsonl")
    device = [e for e in events if e["event"]["dataset"] == "scii.device"]
    assert len(device) == 66
    assert {e["scii"]["report"]["signature"] for e in device} == {"valid"}


def _copy_run(tmp_path, name, run):
    src = _raw(name) / "runs" / run / "device"
    dst = tmp_path / run
    shutil.copytree(src, dst)
    return dst


def _admitted(name):
    from sciitel.export import gate_events

    return gate_events(_raw(name), Profile.load(_raw(name) / "profile.json"))[1]


def test_tampered_report_is_flagged_and_not_reconciled(tmp_path):
    """Изменённый отчёт: подпись недействительна, сверка и изменение версии не вычисляются."""
    dev = _copy_run(tmp_path, "cpslab", "A2-L0")
    path = dev / "reports.jsonl"
    records = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
    genuine = next(e for e in load_events(DATASETS["cpslab"] / "events.jsonl")
                   if e["event"]["action"] == "gate-decision" and e["package"]["version"] == "1.1.0")
    records[1]["event"]["installed_sha256"] = genuine["file"]["hash"]["sha256"]
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records), encoding="utf-8")
    events = device_events(dev, _admitted("cpslab"))
    assert [e["scii"]["report"]["signature"] for e in events] == ["valid", "invalid"]
    assert "reconcile" not in events[1]["scii"]
    assert "svn_change" not in events[1]["scii"]["device"]


def test_signature_covers_canonical_json(tmp_path):
    """Подпись проверяется над тем же представлением, что подписывает устройство стенда."""
    dev = _copy_run(tmp_path, "cpslab", "N1-L2")
    record = json.loads((dev / "reports.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert canonical_json(record["event"]).endswith(b"}\n")
    # порядок ключей в файле не важен: подпись — над каноническим JSON
    shuffled = {"sig": record["sig"], "event": dict(reversed(list(record["event"].items())))}
    (dev / "reports.jsonl").write_text(json.dumps(shuffled, ensure_ascii=False) + "\n", encoding="utf-8")
    assert device_events(dev, _admitted("cpslab"))[0]["scii"]["report"]["signature"] == "valid"


def test_reconciliation_depends_on_gate_log(tmp_path):
    """Без записи о допуске в журнале гейта штатная установка N1 становится недопущенной."""
    home = tmp_path / "home"
    shutil.copytree(_raw("cpslab"), home)
    ledger = home / "gate" / "ledger.jsonl"
    entries = [json.loads(x) for x in ledger.read_text(encoding="utf-8").splitlines()]
    ledger.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in entries if e["serial"] != 2),
                      encoding="utf-8")
    events = export_lab(home, home / "profile.json")
    n1 = [e for e in events if (e.get("labels") or {}).get("cpslab_scenario") == "N1"
          and e["event"]["action"] == "device-install"]
    assert len(n1) == 3 and all(e["scii"]["reconcile"]["admitted"] is False for e in n1)


@pytest.mark.parametrize("scenario, change", [("N1", "increase"), ("A4", "decrease"), ("A6", "same")])
def test_svn_change(scenario, change):
    events = load_events(DATASETS["cpslab"] / "events.jsonl")
    installs = [e for e in events if (e.get("labels") or {}).get("cpslab_scenario") == scenario
                and e["event"]["action"] == "device-install"]
    assert installs
    assert {e["scii"]["device"]["svn_change"] for e in installs} == {change}


def test_compare_ignores_only_volatile_fields():
    events = load_events(DATASETS["cpslab"] / "events.jsonl")
    changed = json.loads(json.dumps(events))
    changed[0]["@timestamp"] = "2030-01-01T00:00:00Z"
    changed[1]["scii"]["evidence"]["reason"] = "другой ключ"
    assert comparable(changed) == comparable(events)
    changed[1]["scii"]["evidence"]["state"] = "refuted"
    assert comparable(changed) != comparable(events)


def _cli(*args):
    return subprocess.run([sys.executable, "-m", "sciitel", *args], cwd=ROOT, capture_output=True, text=True)


def test_cli_validate_and_compare(tmp_path):
    path = DATASETS["cases"] / "events.jsonl"
    assert _cli("validate", str(path)).returncode == 0
    assert _cli("compare", str(path), str(path)).returncode == 0
    events = load_events(path)
    events[0]["scii"]["gate"]["code"] = 30
    other = tmp_path / "other.jsonl"
    write_jsonl(events, other)
    res = _cli("compare", str(path), str(other))
    assert res.returncode == 1 and "различается gate-0001" in res.stdout


def test_cli_index_template():
    res = _cli("index-template")
    assert res.returncode == 0
    assert json.loads(res.stdout) == json.loads((ROOT / "schema" / "index-template.json").read_text(encoding="utf-8"))


def test_cli_bulk():
    res = _cli("bulk", str(DATASETS["cases"] / "events.jsonl"), "--index", "scii-cases")
    lines = res.stdout.splitlines()
    events = load_events(DATASETS["cases"] / "events.jsonl")
    assert res.returncode == 0 and len(lines) == 2 * len(events)
    assert json.loads(lines[0]) == {"index": {"_index": "scii-cases", "_id": events[0]["event"]["id"]}}
    assert json.loads(lines[1]) == events[0]

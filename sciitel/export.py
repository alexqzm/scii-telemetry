"""Выгрузка телеметрии гейта SCII и устройств в события SIEM.

Стенд cps-update-lab. Источники — то, что хранит его сервер обновлений (каталог стенда):

- ``gate/ledger.jsonl`` — журнал решений гейта (по записи на выпуск) и ``gate/runs/*/report.json``
  — отчёт scii-gate по выпуску: состояния и причины 17 свидетельств, вето, границы индекса;
- ``runs/*/device/reports.jsonl`` — подписанные ключом устройства отчёты о попытках установки,
  командах управления и вводе в эксплуатацию; ``device.pk`` — открытый ключ устройства.

Каждая запись становится событием в полях ECS с расширением ``scii.*`` (схема —
``schema/scii-event.schema.json``). Выгрузка добавляет три признака, которых нет в отчёте
устройства и которые нужны правилам обнаружения:

- ``scii.report.signature`` — проверена ли подпись отчёта ключом устройства;
- ``scii.reconcile.admitted`` — допущен ли гейтом установленный образ для класса устройства
  (сверка с журналом решений, как в мониторе стенда);
- ``scii.device.svn_change`` — как изменился номер версии установленного образа по сравнению с
  предыдущим отчётом того же устройства (рост, без изменений, падение).

Сверка и изменение версии вычисляются только для отчётов с действительной подписью.

Стенд ArduPilot (scii-gate, ``testbed/``). Устройства и журнала решений на нём нет: гейт пишет
отчёт по каждому сценарию программы испытаний. Источники — каталог с файлами прогона:
``results.json`` (порядок сценариев, политика, код выхода гейта), ``reports/<сценарий>.json``
(отчёты scii-gate) и ``packages.json`` (плата, версия и SHA-256 пакета ``.apj`` каждого комплекта).
Из них строятся те же события ``gate-decision`` и ``gate-evidence``, что для cps-update-lab.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import SCHEMA_VERSION, __version__

DECISION = {0: "admit", 10: "review", 20: "request", 30: "reject"}
#: решение в отчёте scii-gate → код выхода гейта
DECISION_CODE = {"допуск": 0, "ручное рассмотрение": 10, "запрос свидетельств": 20, "отказ": 30}
#: стенд ArduPilot: префикс event.id (номера решений повторяют номера cps-update-lab) и имя пакета
ARDUPILOT_ID_PREFIX = "ardupilot-"
ARDUPILOT_PRODUCT = "arducopter"
STATE = {"P": "confirmed", "N": "missing", "F": "refuted"}
ENFORCEMENT = {0: "none", 1: "vendor_signature", 2: "scii_receipt"}
DEVICE_ACTION = {"factory": "device-factory", "install": "device-install", "reject": "device-reject",
                 "mgmt": "device-mgmt"}


def canonical_json(obj) -> bytes:
    """Байты, над которыми устройство стенда подписывает отчёт (cpslab.util.canonical_json)."""
    return (json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=1) + "\n").encode("utf-8")


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def _base(timestamp: str, event_id: str, dataset: str, action: str, outcome: str,
          category: list[str], types: list[str]) -> dict:
    return {
        "@timestamp": timestamp,
        "event": {"id": event_id, "kind": "event", "module": "scii", "dataset": dataset,
                  "category": category, "type": types, "action": action, "outcome": outcome},
        "scii": {"schema": SCHEMA_VERSION},
    }


@dataclass
class Profile:
    """Каталог свидетельств профиля политики: имя, стадия, обязательность."""

    evidence: dict

    @classmethod
    def load(cls, path: Path) -> "Profile":
        p = json.loads(Path(path).read_text(encoding="utf-8"))
        stages = {v["id"]: v for v in p["vertices"]}
        evidence = {}
        for vid, items in p["catalog"].items():
            for it in items:
                evidence[it["id"]] = {"name": it["name"], "stage": vid, "stage_name": stages[vid]["name"],
                                      "mandatory": bool(it.get("mandatory")),
                                      "stage_mandatory": bool(stages[vid].get("mandatory"))}
        return cls(evidence)


def decision_events(entry: dict, report: dict, profile: Profile, id_prefix: str = "") -> list[dict]:
    """Событие решения гейта и события 17 свидетельств по записи о решении и отчёту scii-gate.

    Запись — как в журнале стенда cps-update-lab: ``serial``, ``code``, ``device_class``, ``sha256``,
    ``product``, ``version``, ``variant``, ``time``.
    """
    serial, code = int(entry["serial"]), int(entry["code"])
    tool = report.get("tool", "").split(",")[0].split()
    common = {
        "observer": {"vendor": "SCII", "product": "scii-gate", "version": tool[1] if len(tool) > 1 else None},
        "package": {"name": entry["product"], "version": entry["version"]},
        "file": {"hash": {"sha256": entry["sha256"]}},
    }
    gate = {"serial": serial, "variant": entry.get("variant"), "device_class": int(entry["device_class"])}
    ev = _base(entry["time"], f"{id_prefix}gate-{serial:04d}", "scii.gate", "gate-decision", "success",
               ["package"], ["info"])
    ev["event"]["reason"] = DECISION[code]
    ev.update(common)
    g = report.get("G")
    ev["scii"]["gate"] = {**gate, "code": code, "decision": DECISION[code],
                          "veto": True if g == 0 else (False if g == 1 else None),
                          "complete": report.get("B") == 1, "r_min": round(report["R_min"], 4),
                          "r_max": round(report["R_max"], 4), "theta": report["theta"]}
    events = [ev]
    for sid, state in report["states"].items():
        meta = profile.evidence[sid]
        ev = _base(entry["time"], f"{id_prefix}gate-{serial:04d}-{sid}", "scii.gate", "gate-evidence", "success",
                   ["package"], ["info"])
        ev.update(common)
        ev["scii"]["gate"] = dict(gate)
        ev["scii"]["evidence"] = {"id": sid, **meta, "state": STATE[state],
                                  "reason": report.get("reasons", {}).get(sid, "")}
        events.append(ev)
    return events


def gate_events(home: Path, profile: Profile) -> tuple[list[dict], set]:
    """События решений гейта стенда cps-update-lab; множество допущенных пар (класс, SHA-256)."""
    events, admitted = [], set()
    for entry in _jsonl(home / "gate" / "ledger.jsonl"):
        report = json.loads((home / entry["run"] / "report.json").read_text(encoding="utf-8"))
        if int(entry["code"]) == 0:
            admitted.add((int(entry["device_class"]), entry["sha256"]))
        events += decision_events(entry, report, profile)
    return events, admitted


def ardupilot_entries(raw: Path) -> list[tuple[dict, dict]]:
    """Решения прогона стенда ArduPilot в форме записей журнала cps-update-lab, с отчётами scii-gate.

    Номер решения — порядок сценария в ``results.json`` (порядок прогона), код — из решения отчёта,
    время — время отчёта, класс устройства — ``board_id`` пакета (CubeOrange — 140), версия — из
    структуры AP_FWVersion образа (``packages.json``). Код выхода и SHA-256 пакета сверяются с
    ``results.json``: несовпадение означает, что файлы не из одного прогона.
    """
    raw = Path(raw)
    results = json.loads((raw / "results.json").read_text(encoding="utf-8"))
    packages = json.loads((raw / "packages.json").read_text(encoding="utf-8"))
    out = []
    for serial, sc in enumerate(results["scenarios"], 1):
        sid = sc["id"]
        report = json.loads((raw / "reports" / f"{sid}.json").read_text(encoding="utf-8"))
        pkg = packages[sid]
        code = DECISION_CODE[report["decision"]]
        sha = report["artifact"]["sha256"]
        if code != int(sc["exit_code"]):
            raise ValueError(f"{sid}: решение отчёта «{report['decision']}» и код выхода {sc['exit_code']} расходятся")
        if not sha == pkg["sha256"] == sc["artifact_sha256"]:
            raise ValueError(f"{sid}: SHA-256 пакета в отчёте, packages.json и results.json расходятся")
        entry = {"serial": serial, "code": code, "device_class": int(pkg["board_id"]), "sha256": sha,
                 "product": ARDUPILOT_PRODUCT, "version": pkg["version"], "variant": sid,
                 "time": report["time_utc"]}
        out.append((entry, report))
    return out


def export_ardupilot(raw: Path, profile_path: Path) -> list[dict]:
    """События решений гейта стенда ArduPilot: по сценарию — решение и 17 свидетельств."""
    profile = Profile.load(profile_path)
    events = []
    for entry, report in ardupilot_entries(raw):
        events += decision_events(entry, report, profile, ARDUPILOT_ID_PREFIX)
    return events


def device_events(device_dir: Path, admitted: set, labels: dict | None = None) -> list[dict]:
    """События одного устройства по его подписанным отчётам."""
    config = json.loads((device_dir / "config.json").read_text(encoding="utf-8"))
    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex((device_dir / "device.pk").read_text().strip()))
    events, prev_svn = [], None
    for record in _jsonl(device_dir / "reports.jsonl"):
        r = record["event"]
        try:
            pk.verify(base64.b64decode(record["sig"]), canonical_json(r))
            signature = "valid"
        except (InvalidSignature, ValueError):
            signature = "invalid"
        kind = r["event"]
        accepted = bool(r["accepted"])
        category, types = (["configuration"], ["change"]) if kind == "mgmt" else (["package"], ["installation"])
        ev = _base(r["time"], f"{r['device']}-{int(r['seq']):04d}", "scii.device", DEVICE_ACTION[kind],
                   "success" if accepted else "failure", category, types)
        ev["event"]["reason"] = r["reason"]
        ev["event"]["sequence"] = int(r["seq"])
        ev["host"] = {"name": r["device"]}
        level = int(r["level"])
        device = {"class": int(r["device_class"]), "instance": r["instance"], "level": level,
                  "enforcement": ENFORCEMENT.get(level), "path": r["path"],
                  "installed": {"sha256": r.get("installed_sha256"), "version": r.get("installed_version"),
                                "svn": r.get("installed_svn")}}
        if r.get("candidate_sha256"):
            ev["file"] = {"hash": {"sha256": r["candidate_sha256"]}}
        if kind == "install" and r.get("product"):
            ev["package"] = {"name": r["product"], "version": r.get("version")}
        svn = r.get("installed_svn")
        # сверка и изменение версии строятся только на отчётах с действительной подписью: содержимое
        # поддельного отчёта не должно ни поднимать, ни гасить тревоги
        if signature == "valid" and kind in ("install", "factory") and accepted:
            if kind == "install" and prev_svn is not None and svn is not None:
                device["svn_previous"] = prev_svn
                device["svn_change"] = "increase" if svn > prev_svn else ("decrease" if svn < prev_svn else "same")
            ev["scii"]["reconcile"] = {"admitted": (int(r["device_class"]), r.get("installed_sha256")) in admitted}
        if signature == "valid" and svn is not None:
            prev_svn = svn
        ev["scii"]["device"] = device
        ev["scii"]["report"] = {"signature": signature}
        if kind == "mgmt":
            ev["scii"]["mgmt"] = {"command": r.get("command")}
        if labels:
            ev["labels"] = dict(labels)
        ev["observer"] = {"vendor": "SCII", "product": "device-report", "name": config.get("name")}
        events.append(ev)
    return events


def export_lab(home: Path, profile_path: Path) -> list[dict]:
    """Все события каталога стенда: решения гейта, затем устройства прогонов по порядку имён."""
    home = Path(home)
    profile = Profile.load(profile_path)
    events, admitted = gate_events(home, profile)
    for run in sorted((home / "runs").iterdir()):
        device_dir = run / "device"
        if not (device_dir / "reports.jsonl").is_file():
            continue
        scenario, _, level = run.name.rpartition("-L")
        labels = {"cpslab_run": run.name, "cpslab_scenario": scenario, "cpslab_level": level}
        events += device_events(device_dir, admitted, labels)
    return events


def write_jsonl(events: list[dict], path: Path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev, ensure_ascii=False, sort_keys=True) + "\n")


__all__ = ["export_lab", "export_ardupilot", "ardupilot_entries", "decision_events", "gate_events",
           "device_events", "write_jsonl", "canonical_json", "Profile", "__version__"]

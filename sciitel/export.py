"""Выгрузка телеметрии гейта SCII и устройств в события SIEM.

Источники — то, что хранит сервер обновлений стенда cps-update-lab (каталог стенда):

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


def gate_events(home: Path, profile: Profile) -> tuple[list[dict], set]:
    """События решений гейта и свидетельств; множество допущенных пар (класс, SHA-256)."""
    events, admitted = [], set()
    for entry in _jsonl(home / "gate" / "ledger.jsonl"):
        report = json.loads((home / entry["run"] / "report.json").read_text(encoding="utf-8"))
        serial, code = int(entry["serial"]), int(entry["code"])
        if code == 0:
            admitted.add((int(entry["device_class"]), entry["sha256"]))
        tool = report.get("tool", "").split(",")[0].split()
        common = {
            "observer": {"vendor": "SCII", "product": "scii-gate", "version": tool[1] if len(tool) > 1 else None},
            "package": {"name": entry["product"], "version": entry["version"]},
            "file": {"hash": {"sha256": entry["sha256"]}},
        }
        gate = {"serial": serial, "variant": entry.get("variant"), "device_class": int(entry["device_class"])}
        ev = _base(entry["time"], f"gate-{serial:04d}", "scii.gate", "gate-decision", "success",
                   ["package"], ["info"])
        ev["event"]["reason"] = DECISION[code]
        ev.update(common)
        g = report.get("G")
        ev["scii"]["gate"] = {**gate, "code": code, "decision": DECISION[code],
                              "veto": True if g == 0 else (False if g == 1 else None),
                              "complete": report.get("B") == 1, "r_min": round(report["R_min"], 4),
                              "r_max": round(report["R_max"], 4), "theta": report["theta"]}
        events.append(ev)
        for sid, state in report["states"].items():
            meta = profile.evidence[sid]
            ev = _base(entry["time"], f"gate-{serial:04d}-{sid}", "scii.gate", "gate-evidence", "success",
                       ["package"], ["info"])
            ev.update(common)
            ev["scii"]["gate"] = dict(gate)
            ev["scii"]["evidence"] = {"id": sid, **meta, "state": STATE[state],
                                      "reason": report.get("reasons", {}).get(sid, "")}
            events.append(ev)
    return events, admitted


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


__all__ = ["export_lab", "gate_events", "device_events", "write_jsonl", "canonical_json", "Profile",
           "__version__"]

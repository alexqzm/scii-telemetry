"""Набор dataset/ardupilot-0.1.0: решения гейта стенда ArduPilot из репозитория scii-gate.

Стенд ArduPilot входит в scii-gate (``testbed/``): 16 сценариев программы испытаний (ПМИ) на
прошивке ArduPilot Copter-4.5.7 для платы CubeOrange, официальный прогон 30.10.2026. Гейт пишет
отчёт по каждому сценарию; устройства и журнала решений на стенде нет.

  raw   — собрать каталог raw/ из рабочей копии scii-gate: файлы прогона (results.json, отчёты
          scii-gate, план и профиль, SHA-256 ПМИ и плана) и packages.json — плату, версию и
          SHA-256 пакета .apj каждого комплекта data/bundles/<сценарий>, прочитанные функциями
          scii-gate из самого пакета;
  rerun — заново принять решения scii-gate verify по 16 комплектам и сверить отчёты с raw/:
          совпасть должно всё, кроме времени, длительности, версии гейта и поля uncertainty,
          которого нет в отчётах scii-gate 0.1.0; затем собрать из свежих отчётов каталог для
          ``python -m sciitel export-ardupilot``.

  python -m tools.ardupilot raw   --scii-gate DIR --out dataset/ardupilot-0.1.0/raw
  python -m tools.ardupilot rerun --scii-gate DIR --raw dataset/ardupilot-0.1.0/raw --out DIR2

Модуль не зависит от остальной части tools/ (pySigma ему не нужен): его запускают в окружении
scii-gate. Проверка подписи загрузчика (s51) требует pymonocypher 3.1.3.2 — он собирается под
Python 3.11, но не под 3.13; без него гейт ставит s51 в «отсутствует», и rerun это покажет.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

#: файлы прогона: путь в scii-gate → путь в raw/
RUN_FILES = {
    "results/results.json": "results.json",
    "testbed/plan.json": "plan.json",
    "profiles/ardupilot_cubeorange.json": "profile.json",
    "docs/PMI.sha256": "PMI.sha256",
}
PROFILE = "profiles/ardupilot_cubeorange.json"
POLICIES = {"base": "testbed/policy/policy.json", "rotated": "testbed/policy/policy-rotated.json"}
PACKAGE = "package/arducopter.apj"
#: поля отчёта, которые меняются от прогона к прогону или от версии гейта
REPORT_VOLATILE = ("time_utc", "elapsed_s", "tool")
#: поле, которого нет в отчётах scii-gate 0.1.0, и его значение по умолчанию (окрестность N(w))
REPORT_ADDED = {"uncertainty": "neighborhood"}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def scenario_ids(results: dict) -> list[str]:
    return [sc["id"] for sc in results["scenarios"]]


def packages(gate: Path, ids: list[str]) -> dict:
    """Плата, версия и SHA-256 пакета .apj каждого комплекта — функциями scii-gate (scii.checks)."""
    sys.path.insert(0, str(gate))
    try:
        from scii.checks import apj_image, parse_fwversion
    finally:
        sys.path.remove(str(gate))
    out = {}
    for sid in ids:
        path = gate / "data" / "bundles" / sid / PACKAGE
        meta, image = apj_image(str(path))
        fw = parse_fwversion(image)
        if fw is None:
            raise SystemExit(f"{sid}: в образе нет структуры AP_FWVersion")
        out[sid] = {"sha256": _sha256(path), "board_id": int(meta["board_id"]), "board": meta.get("summary"),
                    "git_identity": meta.get("git_identity"),
                    "version": f"{fw['major']}.{fw['minor']}.{fw['patch']}", "fw_type": fw["fw_type"]}
    return out


def cmd_raw(a) -> int:
    gate, out = Path(a.scii_gate), Path(a.out)
    for src, dst in RUN_FILES.items():
        (out / dst).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(gate / src, out / dst)
    results = _json(out / "results.json")
    ids = scenario_ids(results)
    for sid in ids:
        (out / "reports").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(gate / "results" / "reports" / f"{sid}.json", out / "reports" / f"{sid}.json")
    _write_json(out / "packages.json", packages(gate, ids))
    print(f"{out}: файлы прогона {results['started']}…{results['finished']}, отчётов {len(ids)}, пакетов {len(ids)}")
    return 0


def compare_reports(old: dict, new: dict) -> list[str]:
    """Расхождения отчётов, кроме изменчивых полей и поля, добавленного в новых версиях гейта."""
    problems = []
    for key, default in REPORT_ADDED.items():
        if key in new and key not in old and new[key] != default:
            problems.append(f"{key}: {new[key]!r}, ожидалось {default!r}")
    skip = set(REPORT_VOLATILE) | set(REPORT_ADDED)
    for key in sorted((set(old) | set(new)) - skip):
        if old.get(key) != new.get(key):
            problems.append(f"{key}: было {json.dumps(old.get(key), ensure_ascii=False)[:200]}, "
                            f"стало {json.dumps(new.get(key), ensure_ascii=False)[:200]}")
    return problems


def cmd_rerun(a) -> int:
    gate, raw, out = Path(a.scii_gate).resolve(), Path(a.raw), Path(a.out)
    results = _json(raw / "results.json")
    (out / "reports").mkdir(parents=True, exist_ok=True)
    for name in ("results.json", "plan.json", "profile.json", "PMI.sha256"):
        shutil.copyfile(raw / name, out / name)
    env = dict(os.environ, PYTHONPATH=str(gate))
    bad = 0  # сценарии, решение или отчёт которых разошёлся с прогоном
    for sc in results["scenarios"]:
        sid = sc["id"]
        fresh = out / "reports" / f"{sid}.json"
        cmd = [a.python, "-m", "scii", "verify", "--profile", str(gate / PROFILE),
               "--policy", str(gate / POLICIES[sc["policy"]]), "--bundle", str(gate / "data" / "bundles" / sid),
               "--json", str(fresh), "--quiet"]
        code = subprocess.run(cmd, env=env, cwd=gate).returncode
        problems = [] if code == sc["exit_code"] else [f"код выхода {code}, в прогоне {sc['exit_code']}"]
        problems += compare_reports(_json(raw / "reports" / f"{sid}.json"), _json(fresh))
        for p in problems:
            print(f"{sid}: {p}")
        bad += bool(problems)
    pk = packages(gate, scenario_ids(results))
    same_packages = pk == _json(raw / "packages.json")
    if not same_packages:
        print("packages.json: пакеты комплектов не совпали с raw/packages.json")
    _write_json(out / "packages.json", pk)
    total = len(results["scenarios"])
    print(f"решения заново: {total - bad} из {total} совпали с прогоном {results['started']} "
          f"(код выхода, состояния, причины, индексы, решения); пакеты комплектов "
          f"{'совпали' if same_packages else 'НЕ совпали'} с packages.json")
    return 1 if bad or not same_packages else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tools.ardupilot", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("raw", help="собрать raw/ из рабочей копии scii-gate")
    r.add_argument("--scii-gate", required=True, help="рабочая копия scii-gate на закреплённом коммите")
    r.add_argument("--out", required=True)
    r.set_defaults(func=cmd_raw)
    v = sub.add_parser("rerun", help="заново принять решения по 16 комплектам и сверить отчёты с raw/")
    v.add_argument("--scii-gate", required=True)
    v.add_argument("--raw", required=True)
    v.add_argument("--out", required=True)
    v.add_argument("--python", default=sys.executable, help="интерпретатор с зависимостями scii-gate")
    v.set_defaults(func=cmd_rerun)
    a = ap.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())

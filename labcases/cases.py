"""Дополнительные случаи телеметрии на стенде cps-update-lab.

Сценарии стенда (N1, A1–A7, M1, M2) не дают части событий, на которые в репозитории есть
правила: квитанция не разбирается (FORMAT), подписана чужим ключом (KEY), изменена после подписи
(SIGNATURE), несёт решение «отказ» (DECISION) или чужую политику (POLICY); образ короче, чем
записано в квитанции (SIZE); подбор пароля канала управления; подделка отчёта устройства; выпуск
без обязательного свидетельства (решение гейта «запрос свидетельств»).

Случаи воспроизводятся классами стенда (Lab, Device, Gate) с настоящими scii-agent и scii-gate:
квитанции проверяет scii-agent, отчёты подписаны ключами устройств, решение по выпуску принимает
гейт стенда. Поддельные квитанции собираются функциями стенда cpslab.receipt.

Запуск — на копии каталога стенда после ``cpslab --home DIR scenario matrix`` (нужны ключи ролей,
выпуски и решения гейта), с исходниками cps-update-lab в PYTHONPATH:

  PYTHONPATH=<cps-update-lab> python labcases/cases.py --home <копия каталога стенда>

Прогоны сценариев стенда из копии удаляются: в каталоге остаются решения гейта и прогоны случаев.
Выход 0 — каждый случай дал ожидаемый исход.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import shutil
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cpslab.image import svn
from cpslab.receipt import HEADER_LEN, PAYLOAD_LEN, issue, parse
from cpslab.scenarios import TANK, Lab
from cpslab.util import sha256_bytes, wjson

#: случай → (что происходит, ожидаемый исход)
CASES = {
    "C1": ("квитанция обрезана до 100 байт", "FORMAT"),
    "C2": ("квитанция подписана ключом нарушителя", "KEY"),
    "C3": ("в подлинной квитанции поднят номер версии", "SIGNATURE"),
    "C4": ("квитанция с решением «отказ», подписанная ключом гейта", "DECISION"),
    "C5": ("квитанция под другую политику, подписанная ключом гейта", "POLICY"),
    "C6": ("образ короче на байт, квитанция подлинная", "SIZE"),
    "C7": ("подбор пароля канала управления, затем команда stop с паролем по умолчанию", "DENIED, DENIED, DENIED, OK"),
    "C8": ("L0 установил вредоносный образ, в отчёте подменён SHA-256 образа на допущенный", "OK, отчёт подделан"),
    "C9": ("выпуск ТК-1 1.1.0 без аттестации происхождения s22", "решение 20"),
}

GENUINE = "tank-1.1.0"
NO_PROVENANCE = "tank-1.1.0-no-provenance"
OTHER_POLICY = hashlib.sha256("cpslab: другая политика".encode()).digest()
GUESSES = ("1234", "password", "plc")


def _payload_edit(receipt: bytes, **changes) -> bytes:
    """Квитанция с изменённой нагрузкой и прежней подписью."""
    body = dataclasses.replace(parse(receipt), **changes).pack()
    return receipt[:HEADER_LEN] + body + receipt[HEADER_LEN + PAYLOAD_LEN:]


def _update_l2(lab: Lab, rid: str, receipt=None, image=None) -> dict:
    """Устройство L2 с ТК-1 1.0.0 забирает пакет 1.1.0, в котором подменены квитанция или образ."""
    dev = lab.device(rid, 2, "tank-1.0.0")
    store = lab.store(rid)
    lab.publish(store, GENUINE)
    if receipt is not None:
        store.write(TANK, "receipt.scr", receipt(lab.receipt(GENUINE)))
    if image is not None:
        store.write(TANK, "image.bin", image(lab.image(GENUINE)))
    return dev.check_update(store)


def case_receipts(lab: Lab) -> dict:
    gate_sk = lab.keys.gate_key()
    edits = {
        "C1": dict(receipt=lambda r: r[:100]),
        "C2": dict(receipt=lambda r: issue(Ed25519PrivateKey.generate(), parse(r))),
        "C3": dict(receipt=lambda r: _payload_edit(r, svn=parse(r).svn + (1 << 16))),
        "C4": dict(receipt=lambda r: issue(gate_sk, dataclasses.replace(parse(r), decision=30))),
        "C5": dict(receipt=lambda r: issue(gate_sk, dataclasses.replace(parse(r), policy_digest=OTHER_POLICY))),
        "C6": dict(image=lambda img: img[:-1]),
    }
    return {cid: _update_l2(lab, f"{cid}-L2", **kw)["reason"] for cid, kw in edits.items()}


def case_password(lab: Lab) -> str:
    dev = lab.device("C7-L2", 2, "tank-1.1.0")
    reasons = [dev.mgmt("stop", pw)["reason"] for pw in GUESSES]
    reasons.append(dev.mgmt("stop", dev.config["mgmt_password"])["reason"])
    return ", ".join(reasons)


def case_forged_report(lab: Lab) -> str:
    rid = "C8-L0"
    dev = lab.device(rid, 0, "tank-1.0.0")
    store = lab.store(rid)
    lab.publish(store, "tank-1.1.0-stolen-key")
    res = dev.check_update(store)
    genuine = sha256_bytes(lab.image(GENUINE))
    path = dev.root / "reports.jsonl"
    records = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    forged = records[-1]["event"]
    if forged["event"] != "install":
        raise SystemExit(f"{rid}: последний отчёт — {forged['event']}, ожидалась установка")
    forged["candidate_sha256"] = forged["installed_sha256"] = genuine  # подпись остаётся прежней
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records), encoding="utf-8")
    return f"{res['reason']}, отчёт подделан"


def case_no_provenance(lab: Lab) -> str:
    src = lab.release(GENUINE)
    dst = lab.vendor.releases / NO_PROVENANCE
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst)
    bundle = json.loads((dst / "bundle.json").read_text(encoding="utf-8"))
    (dst / bundle["evidence"].pop("s22")["attestation"]).unlink()
    bundle["release"]["variant"] = NO_PROVENANCE
    wjson(dst / "bundle.json", bundle)
    res = lab.gate.admit(dst, {"device_class": TANK, "installed_svn": svn("1.0.0")})
    return f"решение {res['code']}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--home", required=True, type=Path, help="копия каталога стенда после scenario matrix")
    args = parser.parse_args(argv)
    lab = Lab(args.home)
    if not (lab.home / "lab.json").exists():
        print(f"{lab.home}: нет lab.json — сначала cpslab --home {lab.home} scenario matrix")
        return 2
    shutil.rmtree(lab.home / "runs", ignore_errors=True)
    got = case_receipts(lab)
    got["C7"] = case_password(lab)
    got["C8"] = case_forged_report(lab)
    got["C9"] = case_no_provenance(lab)
    bad = 0
    for cid, (what, want) in CASES.items():
        ok = got[cid] == want
        bad += not ok
        print(f"{cid} {what}: {got[cid]}" + ("" if ok else f" — ожидалось {want}"))
    wjson(lab.home / "cases.json", {cid: {"case": what, "expected": want, "outcome": got[cid]}
                                     for cid, (what, want) in CASES.items()})
    print(f"случаев: {len(CASES)}, не совпало с ожиданием: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

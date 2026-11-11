"""Командная строка scii-telemetry.

  python -m sciitel export --lab-home DIR --profile profile.json --out events.jsonl [--provenance FILE]
  python -m sciitel export-ardupilot --raw DIR --profile profile.json --out events.jsonl [--provenance FILE]
  python -m sciitel validate events.jsonl [...]
  python -m sciitel compare A.jsonl B.jsonl [--ignore FIELD ...]  # совпадают ли наборы без изменчивых полей
  python -m sciitel index-template [--out FILE]  # шаблон индекса OpenSearch и Elasticsearch по схеме
  python -m sciitel bulk events.jsonl --index scii-lab > bulk.ndjson  # тело запроса _bulk
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import SCHEMA_VERSION, __version__
from .export import export_ardupilot, export_lab, write_jsonl
from .schema import comparable, index_template, load_events, validate


def cmd_export(a) -> int:
    return _write_export(export_lab(Path(a.lab_home), Path(a.profile)), a)


def cmd_export_ardupilot(a) -> int:
    return _write_export(export_ardupilot(Path(a.raw), Path(a.profile)), a)


def _write_export(events: list[dict], a) -> int:
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(events, out)
    problems = validate(events)
    for p in problems[:20]:
        print(p, file=sys.stderr)
    by = {}
    for ev in events:
        by[ev["event"]["dataset"]] = by.get(ev["event"]["dataset"], 0) + 1
    print(f"{out}: событий {len(events)} ({', '.join(f'{k}: {v}' for k, v in sorted(by.items()))}), "
          f"нарушений схемы {len(problems)}")
    if a.provenance:
        prov = json.loads(Path(a.provenance).read_text(encoding="utf-8")) if Path(a.provenance).exists() else {}
        prov.update({"exporter": f"scii-telemetry {__version__}", "schema": SCHEMA_VERSION,
                     "events": len(events), "datasets": by})
        Path(a.provenance).write_text(json.dumps(prov, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 1 if problems else 0


def cmd_validate(a) -> int:
    bad = 0
    for path in a.files:
        problems = validate(load_events(Path(path)))
        for p in problems[:20]:
            print(f"{path}: {p}")
        print(f"{path}: нарушений схемы {len(problems)}")
        bad += len(problems)
    return 1 if bad else 0


def cmd_compare(a) -> int:
    ignore = tuple(a.ignore or ())
    left, right = (comparable(load_events(Path(p)), ignore) for p in (a.left, a.right))
    if left == right:
        extra = f" и {', '.join(ignore)}" if ignore else ""
        print(f"наборы совпадают без изменчивых полей{extra}: {len(left)} событий")
        return 0
    lk, rk = set(left), set(right)
    for k in sorted(lk - rk)[:20]:
        print(f"только в {a.left}: {k}")
    for k in sorted(rk - lk)[:20]:
        print(f"только в {a.right}: {k}")
    diff = [k for k in sorted(lk & rk) if left[k] != right[k]]
    for k in diff[:20]:
        print(f"различается {k}:\n  {json.dumps(left[k], ensure_ascii=False, sort_keys=True)}\n"
              f"  {json.dumps(right[k], ensure_ascii=False, sort_keys=True)}")
    print(f"различий: {len(lk ^ rk) + len(diff)}")
    return 1


def cmd_index_template(a) -> int:
    text = json.dumps(index_template(), ensure_ascii=False, indent=2) + "\n"
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


def cmd_bulk(a) -> int:
    for ev in load_events(Path(a.events)):
        sys.stdout.write(json.dumps({"index": {"_index": a.index, "_id": ev["event"]["id"]}}) + "\n")
        sys.stdout.write(json.dumps(ev, ensure_ascii=False, sort_keys=True) + "\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sciitel", description="телеметрия гейта SCII и устройств КФС для SIEM")
    ap.add_argument("--version", action="version", version=f"scii-telemetry {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export", help="выгрузить события из каталога стенда cps-update-lab")
    e.add_argument("--lab-home", required=True)
    e.add_argument("--profile", required=True, help="профиль политики гейта (каталог свидетельств)")
    e.add_argument("--out", required=True)
    e.add_argument("--provenance", help="дописать сведения о выгрузке в этот JSON")
    e.set_defaults(func=cmd_export)
    r = sub.add_parser("export-ardupilot", help="выгрузить решения гейта стенда ArduPilot из файлов прогона scii-gate")
    r.add_argument("--raw", required=True, help="каталог прогона: results.json, reports/, packages.json")
    r.add_argument("--profile", required=True, help="профиль политики гейта (каталог свидетельств)")
    r.add_argument("--out", required=True)
    r.add_argument("--provenance", help="дописать сведения о выгрузке в этот JSON")
    r.set_defaults(func=cmd_export_ardupilot)
    v = sub.add_parser("validate", help="проверить события по схеме")
    v.add_argument("files", nargs="+")
    v.set_defaults(func=cmd_validate)
    c = sub.add_parser("compare", help="сравнить наборы событий без изменчивых полей")
    c.add_argument("left")
    c.add_argument("right")
    c.add_argument("--ignore", action="append", metavar="FIELD",
                   help="не сравнивать ещё и это поле (имя через точку), можно несколько раз")
    c.set_defaults(func=cmd_compare)
    t = sub.add_parser("index-template", help="шаблон индекса OpenSearch и Elasticsearch по схеме событий")
    t.add_argument("--out", help="записать в файл (по умолчанию — в stdout)")
    t.set_defaults(func=cmd_index_template)
    b = sub.add_parser("bulk", help="тело запроса _bulk OpenSearch и Elasticsearch (_id — event.id)")
    b.add_argument("events")
    b.add_argument("--index", required=True, help="индекс; шаблон index-template подходит к scii-*")
    b.set_defaults(func=cmd_bulk)
    a = ap.parse_args(argv)
    return a.func(a)

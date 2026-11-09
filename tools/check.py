"""Проверка правил: валидаторы pySigma с закреплённой MITRE ATT&CK и сверка со схемой событий.

Правила размечены техниками двух матриц ATT&CK — Enterprise (T1195.002, T1689, T1110) и ICS (T0862,
T1693.001, T0843…). Валидатор тегов pySigma читает одну матрицу, поэтому здесь объекты обеих
закреплённых матриц attack-stix-data 20.1 сливаются в один файл; хеши файлов сверяются до загрузки.

Сверх валидаторов pySigma проверяется:

- каждое поле условий и группировки корреляций есть в схеме событий schema/scii-event.schema.json,
  а значения полей с перечислением в схеме входят в перечисление (опечатка в коде отказа не пройдёт);
- каждая техника правила относится хотя бы к одной тактике правила, и каждая тактика подкреплена
  техникой (по фазам kill chain обеих матриц);
- источник правила — product: scii, service: gate или device: только их знает конвейер полей.

usage: python -m tools.check --attack-enterprise enterprise-attack-20.1.json --attack-ics ics-attack-20.1.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.data import mitre_attack
from sigma.plugins import InstalledSigmaPlugins
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule
from sigma.types import SigmaBool, SigmaNull, SigmaNumber, SigmaString
from sigma.validation import SigmaValidator

from .common import RULES

ATTACK_VERSION = "20.1"
ATTACK_COMMIT = "a8db2f52eb933c9c99060c123e088b3326d3a607"
ATTACK = {
    "enterprise": ("enterprise-attack/enterprise-attack-20.1.json",
                   "539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5"),
    "ics": ("ics-attack/ics-attack-20.1.json",
            "3f6448369f9135ade84ff6437479441530d0b262f910dca991879a7146b524ff"),
}
KILL_CHAINS = ("mitre-attack", "mitre-ics-attack")
SCHEMA = Path(__file__).resolve().parent.parent / "schema" / "scii-event.schema.json"
SOURCES = {("scii", "gate"), ("scii", "device")}

#: валидаторы pySigma, которые не применяются, и причины
EXCLUDED: dict[str, str] = {}


# ---------------- ATT&CK ----------------
def load_attack(paths: dict[str, Path]) -> tuple[list[dict], list[str]]:
    """Объекты обеих матриц и ошибки сверки хешей."""
    objects, errors = [], []
    for domain, path in paths.items():
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != ATTACK[domain][1]:
            errors.append(f"{path}: SHA-256 {digest}, ожидался {ATTACK[domain][1]} ({ATTACK[domain][0]})")
            continue
        objects += json.loads(data)["objects"]
    return objects, errors


def technique_tactics(objects: list[dict]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next((r.get("external_id") for r in obj.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if ext:
            out.setdefault(ext.lower(), set()).update(
                p["phase_name"] for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") in KILL_CHAINS)
    return out


def check_tactics(rule, mapping: dict[str, set[str]]) -> list[str]:
    tags = [t.name for t in rule.tags if t.namespace == "attack"]
    techniques = [t for t in tags if re.fullmatch(r"t\d{4}(\.\d{3})?", t)]
    tactics = {t for t in tags if t not in techniques and not re.fullmatch(r"[gs]\d{4}", t)}
    problems = []
    for tech in techniques:
        if not mapping.get(tech, set()) & tactics:
            problems.append(f"техника {tech.upper()} не относится ни к одной тактике правила "
                            f"({', '.join(sorted(mapping.get(tech, set()))) or 'нет в матрицах'})")
    for tac in sorted(tactics):
        if not any(tac in mapping.get(tech, set()) for tech in techniques):
            problems.append(f"тактика {tac} не подкреплена ни одной техникой правила")
    return problems


# ---------------- схема событий ----------------
def schema_fields(schema: dict) -> dict[str, set | None]:
    """Поле через точку → допустимые значения (объединение перечислений схемы) или None."""
    defs = schema.get("$defs", {})
    out: dict[str, set | None] = {}

    def resolve(node: dict) -> dict:
        while "$ref" in node:
            node = defs[node["$ref"].rsplit("/", 1)[-1]]
        return node

    def leaf(path: str, node: dict) -> None:
        # перечисление поля — объединение перечислений всех ветвей схемы, где оно задано (event.reason
        # уточняется в условных ветвях для решений гейта и отчётов устройств)
        values = node.get("enum")
        if values is None and "const" in node:
            values = [node["const"]]
        if values is None and isinstance(node.get("items"), dict):
            values = resolve(node["items"]).get("enum")
        branches = [resolve(b) for b in node.get("oneOf", []) + node.get("anyOf", [])]
        if values is None and branches and all("enum" in b or b.get("type") == "null" for b in branches):
            values = [v for b in branches for v in b.get("enum", [])]
        if values is None:
            out.setdefault(path, None)
        else:
            out[path] = (out.get(path) or set()) | set(values)

    def walk(node: dict, path: str) -> None:
        node = resolve(node)
        for branch in node.get("allOf", []):
            walk(branch.get("then", {}), path)
        if "properties" in node:
            for key, sub in node["properties"].items():
                walk(sub, f"{path}.{key}" if path else key)
        elif path and any(k in node for k in ("type", "enum", "const", "items", "oneOf", "anyOf")) \
                and node.get("type") != "object":
            leaf(path, node)

    walk(schema, "")
    return out


def _items(detection: SigmaDetection):
    for item in detection.detection_items:
        if isinstance(item, SigmaDetection):
            yield from _items(item)
        else:
            yield item


def _plain(value):
    if isinstance(value, SigmaBool):
        return value.boolean
    if isinstance(value, SigmaNumber):
        return value.number
    if isinstance(value, SigmaString):
        return None if value.contains_special() else str(value)
    if isinstance(value, SigmaNull):
        return None
    return None


def check_fields(rule, fields: dict[str, set | None]) -> list[str]:
    problems = []
    if isinstance(rule, SigmaCorrelationRule):
        for name in rule.group_by or []:
            if name not in fields:
                problems.append(f"поля группировки {name} нет в схеме событий")
        return problems
    for detection in rule.detection.detections.values():
        for item in _items(detection):
            item: SigmaDetectionItem
            if item.field is None:
                problems.append("поиск по всем полям (без имени поля) схемой не проверяется")
                continue
            if item.field not in fields:
                problems.append(f"поля {item.field} нет в схеме событий")
                continue
            allowed = fields[item.field]
            for value in item.value:
                plain = _plain(value)
                if allowed is not None and plain is not None and plain not in allowed:
                    problems.append(f"{item.field}: значения {plain!r} нет среди допустимых схемой")
    return problems


def check_source(rule) -> list[str]:
    if isinstance(rule, SigmaCorrelationRule):
        return []
    src = (rule.logsource.product, rule.logsource.service)
    return [] if src in SOURCES else [f"источник {src} не обрабатывается конвейером полей"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--attack-enterprise", type=Path, required=True, help=ATTACK["enterprise"][0])
    parser.add_argument("--attack-ics", type=Path, required=True, help=ATTACK["ics"][0])
    args = parser.parse_args(argv)

    objects, errors = load_attack({"enterprise": args.attack_enterprise, "ics": args.attack_ics})
    for err in errors:
        print(err)
    if errors:
        return 2
    cache = tempfile.TemporaryDirectory(prefix="pysigma-attack-")
    merged = Path(cache.name) / "attack-enterprise-ics.json"
    merged.write_text(json.dumps({"type": "bundle", "objects": objects}), encoding="utf-8")
    mitre_attack.set_cache_dir(Path(cache.name) / "cache")
    mitre_attack.set_url(str(merged))
    if mitre_attack.mitre_attack_version != ATTACK_VERSION:
        print(f"загружена ATT&CK {mitre_attack.mitre_attack_version}, ожидалась {ATTACK_VERSION}")
        return 2

    collection = SigmaCollection.load_ruleset([RULES], collect_errors=True)
    parse_errors = [(rule, err) for rule in collection.rules for err in rule.errors]
    for rule, err in parse_errors:
        print(f"ошибка разбора: {rule.source}: {err}")

    validators = InstalledSigmaPlugins.autodiscover().validators
    unknown = set(EXCLUDED) - set(validators)
    if unknown:
        print(f"неизвестные валидаторы в исключениях: {sorted(unknown)}")
        return 2
    used = {name: cls for name, cls in validators.items() if name not in EXCLUDED}
    issues = SigmaValidator(used.values()).validate_rules(collection.rules)
    for issue in issues:
        rules = ", ".join(str(r.source.path.relative_to(RULES.parent)) if r.source else str(r.id)
                          for r in issue.rules)
        print(f"{issue.severity.name}: {type(issue).__name__}: {issue.description} — {rules}")

    fields = schema_fields(json.loads(SCHEMA.read_text(encoding="utf-8")))
    tactics = technique_tactics(objects)
    own = 0
    for rule in collection.rules:
        if not isinstance(rule, (SigmaRule, SigmaCorrelationRule)):
            continue
        where = rule.source.path.relative_to(RULES.parent) if rule.source else rule.id
        for problem in check_fields(rule, fields) + check_tactics(rule, tactics) + check_source(rule):
            print(f"{where} ({rule.title}): {problem}")
            own += 1

    print(f"правил: {len(collection.rules)}, валидаторов pySigma: {len(used)} (ATT&CK {ATTACK_VERSION}: "
          f"Enterprise и ICS), ошибок разбора: {len(parse_errors)}, замечаний валидаторов: {len(issues)}, "
          f"замечаний по схеме и тактикам: {own}")
    for name, reason in sorted(EXCLUDED.items()):
        print(f"  не применяется {name}: {reason}")
    cache.cleanup()
    return 1 if parse_errors or issues or own else 0


if __name__ == "__main__":
    sys.exit(main())

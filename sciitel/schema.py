"""Проверка событий по JSON Schema и сравнение наборов без изменчивых полей."""

from __future__ import annotations

import copy
import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

SCHEMA = Path(__file__).resolve().parent.parent / "schema" / "scii-event.schema.json"

#: поля, которые меняются от прогона к прогону стенда: время и тексты причин с номерами ключей
#: и коммитов (ключи ролей стенд создаёт заново, а подпись входит в объект коммита)
VOLATILE = (("@timestamp",), ("scii", "evidence", "reason"))


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate(events: list[dict]) -> list[str]:
    out = []
    for n, ev in enumerate(events, 1):
        for err in _validator().iter_errors(ev):
            where = "/".join(str(x) for x in err.absolute_path) or "(корень)"
            out.append(f"событие {n} ({ev.get('event', {}).get('id')}): {where}: {err.message}")
    return out


def load_events(path: Path) -> list[dict]:
    return [json.loads(x) for x in Path(path).read_text(encoding="utf-8").splitlines() if x.strip()]


def _es_type(node: dict, resolve) -> str:
    """Тип поля OpenSearch и Elasticsearch для листа схемы."""
    node = resolve(node)
    branches = [resolve(b) for b in node.get("oneOf", []) + node.get("anyOf", []) if resolve(b).get("type") != "null"]
    if branches:
        return _es_type(branches[0], resolve)
    values = node.get("enum", [node["const"]] if "const" in node else None)
    if values is not None:
        if all(isinstance(v, bool) for v in values):
            return "boolean"
        if all(isinstance(v, int) and not isinstance(v, bool) for v in values):
            return "long"
        return "keyword"
    kind = node.get("type")
    if isinstance(kind, list):
        kind = next(k for k in kind if k != "null")
    if kind == "array":
        return _es_type(node["items"], resolve)
    return {"string": "keyword", "integer": "long", "number": "double", "boolean": "boolean"}[kind]


def index_template() -> dict:
    """Шаблон индекса для OpenSearch и Elasticsearch по схеме событий (PUT _index_template/<имя>).

    Строки — keyword (поиск по точному значению, как в запросах из conversions/), целые — long,
    дробные — double, @timestamp — date. dynamic: strict — событие с полем вне схемы не индексируется;
    исключение — labels (метки стенда, произвольные строки).
    """
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    defs = schema.get("$defs", {})

    def resolve(node: dict) -> dict:
        while "$ref" in node:
            node = defs[node["$ref"].rsplit("/", 1)[-1]]
        return node

    def props(node: dict) -> dict:
        out = {}
        for key, sub in resolve(node).get("properties", {}).items():
            sub = resolve(sub)
            if sub.get("type") == "object" and "properties" in sub:
                out[key] = {"properties": props(sub)}
            elif sub.get("type") == "object":
                out[key] = {"type": "object", "dynamic": True}
            else:
                out[key] = {"type": _es_type(sub, resolve)}
        return out

    mappings = {
        "dynamic": "strict",
        "dynamic_templates": [{"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword"}}}],
        "properties": props(schema),
    }
    mappings["properties"]["@timestamp"] = {"type": "date"}
    return {
        "index_patterns": ["scii-*"],
        "template": {"mappings": mappings},
        "_meta": {"description": f"{schema['title']}; сгенерирован python -m sciitel index-template",
                  "schema": schema["properties"]["scii"]["properties"]["schema"]["const"]},
    }


def comparable(events: list[dict], ignore: tuple[str, ...] = ()) -> dict[str, dict]:
    """event.id → событие без изменчивых полей и без полей ``ignore`` (имена через точку)."""
    paths = VOLATILE + tuple(tuple(name.split(".")) for name in ignore)
    out = {}
    for ev in events:
        ev = copy.deepcopy(ev)
        for path in paths:
            node = ev
            for key in path[:-1]:
                node = node.get(key, {})
            node.pop(path[-1], None)
        out[ev["event"]["id"]] = ev
    return out

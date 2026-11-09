"""Интеграционная проверка запросов из conversions/ в OpenSearch и Elasticsearch.

Наборы событий (dataset/cpslab-0.1.0, dataset/cases-0.1.0 и синтетическое событие) по очереди
загружаются в индекс, и движок исполняет запросы из conversions/: Lucene через query_string, в
Elasticsearch ещё EQL (_eql/search) и ES|QL (_query). Найденные события должны совпасть с теми, на
которых правило срабатывает в стенде tools.harness; для корреляции сравниваются группы (значения
полей group-by), в которых она срабатывает. В кластере в каждый момент один индекс с событиями:
запросы ES|QL читают индексы scii-*.

Сопоставление полей задаёт шаблон индекса schema/index-template.json (его ставит эта проверка —
так в обоих движках проверяется и сам шаблон): строки — keyword (точное совпадение с учётом
регистра; коды и действия в событиях в том же регистре, что в правилах), @timestamp — date. Без
явного сопоставления запросы EQL и ES|QL падают на полях, которых нет в загруженном наборе.

Отчёты устройства датированы с точностью до секунды, поэтому последовательности EQL из отчётов
одного устройства (группировка по host.name) получают tiebreaker_field: event.sequence — номер
отчёта устройства: иначе отчёты одной секунды не образуют последовательность. Для последовательности
«решение гейта → установка» общего счётчика нет; события одной секунды EQL без tiebreaker_field
упорядочивает по порядку индексации (решения гейта загружаются первыми, как они и записаны).

Известные расхождения перечислены в tools/known_issues.py с причиной: такой случай не роняет
проверку, а неожиданный успех в нём — роняет, чтобы список не устаревал.

usage: python -m tools.siem_it --engine opensearch --url http://localhost:9200 [--report FILE]
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

from .common import CONVERSIONS, DATASETS, ROOT, SYNTHETIC, dataset_events, load_jsonl, rule_files, strip_test
from .harness import Harness
from .known_issues import lookup

INDEX = "scii-telemetry-it"  # подпадает под index_patterns шаблона: scii-*
TEMPLATE = "scii-telemetry"
TEMPLATE_FILE = ROOT / "schema" / "index-template.json"
SETTINGS = {"settings": {"number_of_shards": 1, "number_of_replicas": 0}}
TIEBREAKER = "event.sequence"
LANGUAGES = {  # движок → (каталог conversions/, расширение, язык)
    "opensearch": [("opensearch", "lucene", "lucene")],
    "elasticsearch": [("elasticsearch", "lucene", "lucene"), ("elasticsearch-eql", "eql", "eql"),
                      ("elasticsearch-esql", "esql", "esql")],
}


class Engine:
    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, method: str, path: str, body=None, ndjson: str | None = None):
        data, ctype = None, "application/json"
        if ndjson is not None:
            data, ctype = ndjson.encode(), "application/x-ndjson"
        elif body is not None:
            data = json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=data, method=method, headers={"Content-Type": ctype})
        try:
            with self.opener.open(req, timeout=120) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def info(self) -> str:
        _, body = self.call("GET", "/")
        ver = body.get("version", {})
        return f"{ver.get('distribution', 'elasticsearch')} {ver.get('number')}"


def install_template(engine: Engine) -> None:
    body = json.loads(TEMPLATE_FILE.read_text(encoding="utf-8"))
    status, resp = engine.call("PUT", f"/_index_template/{TEMPLATE}", body)
    if status != 200:
        raise RuntimeError(f"шаблон индекса: {status} {resp}")


def load_index(engine: Engine, events: list[dict]) -> None:
    engine.call("DELETE", f"/{INDEX}")
    status, body = engine.call("PUT", f"/{INDEX}", SETTINGS)
    if status != 200:
        raise RuntimeError(f"создание индекса: {status} {body}")
    lines = []
    for ev in events:
        lines.append(json.dumps({"index": {"_index": INDEX, "_id": ev["event"]["id"]}}))
        lines.append(json.dumps(strip_test(ev), ensure_ascii=False))
    status, body = engine.call("POST", "/_bulk?refresh=true", ndjson="\n".join(lines) + "\n")
    if status != 200 or body.get("errors"):
        raise RuntimeError(f"загрузка: {status} {json.dumps(body, ensure_ascii=False)[:500]}")


def _reason(body: dict) -> str:
    err = body.get("error", {})
    if isinstance(err, dict):
        root = (err.get("root_cause") or [{}])[0]
        return (root.get("reason") or err.get("reason") or str(err))[:300]
    return str(err)[:300]


def run_query(engine: Engine, lang: str, query: str, group_by: list[str] | None):
    """(найденное, ошибка): множество event.id или, для корреляции, множество групп."""
    tiebreaker = {"tiebreaker_field": TIEBREAKER} if group_by and "host.name" in group_by else {}
    if lang == "lucene":
        status, body = engine.call("POST", f"/{INDEX}/_search",
                                   {"query": {"query_string": {"query": query}}, "size": 1000, "_source": False})
        if status != 200:
            return None, f"HTTP {status}: {_reason(body)}"
        return {h["_id"] for h in body["hits"]["hits"]}, ""
    if lang == "eql":
        status, body = engine.call("POST", f"/{INDEX}/_eql/search",
                                   {"query": query, "size": 1000, **tiebreaker})
        if status != 200:
            return None, f"HTTP {status}: {_reason(body)}"
        hits = body["hits"]
        if group_by is not None:
            return {tuple(str(v) for v in s.get("join_keys") or []) for s in hits.get("sequences", [])}, ""
        return {e["_id"] for e in hits.get("events", [])}, ""
    status, body = engine.call("POST", "/_query", {"query": query})
    if status != 200:
        return None, f"HTTP {status}: {_reason(body)}"
    names = [c["name"] for c in body["columns"]]
    if group_by is not None:
        return {tuple(str(row[names.index(f)]) for f in group_by) for row in body["values"]}, ""
    return {row[names.index("_id")] for row in body["values"]}, ""


def expected(h: Harness, events: list[dict], rf) -> set:
    if rf.correlation:
        return {tuple(str(v) for v in key) for key in h.correlate(rf.correlation)}
    return {events[i]["event"]["id"] for i in h.match(rf.base_rules[0])}


def run(engine_name: str, url: str) -> tuple[list[dict], str]:
    engine = Engine(url)
    version = engine.info()
    sets = {name: dataset_events(name) for name in DATASETS}
    sets["synthetic"] = load_jsonl(SYNTHETIC)
    rfs = rule_files()
    results: dict[tuple[str, str], dict] = {}
    install_template(engine)
    for set_name, events in sets.items():
        h = Harness(events)
        load_index(engine, events)
        for rf in rfs:
            group_by = list(rf.correlation.group_by) if rf.correlation else None
            want = expected(h, events, rf)
            for folder, ext, lang in LANGUAGES[engine_name]:
                path = CONVERSIONS / folder / f"{rf.key}.{ext}"
                if not path.is_file():
                    continue
                query = path.read_text(encoding="utf-8").strip()
                got, error = run_query(engine, lang, query, group_by)
                res = results.setdefault((folder, rf.key), {
                    "rule": rf.key, "target": folder, "ok": True, "errors": [], "diffs": [], "fixed": None,
                    "found": 0})
                if got is None:
                    res["ok"] = False
                    res["errors"].append(f"{set_name}: {error}")
                elif got != want:
                    res["ok"] = False
                    res["diffs"].append(f"{set_name}: лишние {sorted(map(str, got - want))[:5]}, "
                                        f"не найдены {sorted(map(str, want - got))[:5]}")
                else:
                    res["found"] += len(got)
                known = lookup(folder, rf.key)
                if known and known.fix:
                    patched = known.apply(query)
                    if patched is None:
                        res["fixed"] = "в запросе нет подстроки из правки"
                    elif res["fixed"] in (None, True):
                        fixed, _ = run_query(engine, lang, patched, group_by)
                        res["fixed"] = True if fixed == want else f"не прошёл на {set_name}"
        engine.call("DELETE", f"/{INDEX}")
    engine.call("DELETE", f"/_index_template/{TEMPLATE}")
    out = []
    for (folder, key), res in sorted(results.items()):
        known = lookup(folder, key)
        res["known"] = known.reason if known else None
        res["fix"] = [list(f) for f in known.fix] if known and known.fix else None
        out.append(res)
    return out, version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--engine", choices=tuple(LANGUAGES), required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--report", help="дописать таблицу результатов в этот файл (Markdown)")
    args = parser.parse_args(argv)
    results, version = run(args.engine, args.url)
    unexpected = [r for r in results if r["ok"] == bool(r["known"]) or (r["fix"] and r["fixed"] is not True)]
    rows = [f"### {version}", "", "| Правило | Запрос | Итог |", "|---|---|---|"]
    for r in results:
        if r["ok"] and not r["known"]:
            verdict = f"совпало со стендом (найдено {r['found']})"
        elif r["ok"]:
            verdict = f"**неожиданно совпало** (в known_issues: {r['known']})"
        elif r["known"]:
            where = "; ".join(r["errors"] + r["diffs"]).replace("\n", " ")
            verdict = f"известное расхождение: {r['known']} ({where[:300]})"
            if r["fix"]:
                fixed = "проходит" if r["fixed"] is True else f"**{r['fixed']}**"
                edits = ", ".join(f"«{old.strip()}» → «{new.strip()}»" for old, new in r["fix"])
                verdict += f"; запрос с правкой {edits} {fixed}"
        else:
            verdict = f"**расхождение**: {'; '.join(r['errors'] + r['diffs'])}"
        rows.append(f"| `{r['rule']}` | `{r['target']}` | {verdict.replace('|', chr(92) + '|')} |")
    rows += ["", f"Проверено пар «правило — запрос»: {len(results)}, неожиданных исходов: {len(unexpected)}.", ""]
    text = "\n".join(rows)
    print(text)
    for r in unexpected:
        print(json.dumps(r, ensure_ascii=False))
    if args.report:
        with open(args.report, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main())

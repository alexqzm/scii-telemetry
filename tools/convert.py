"""Конвертация правил в запросы SIEM официальными бэкендами pySigma с конвейером полей репозитория.

Запросы лежат в conversions/<цель>/<правило>.<расширение>; там же README.md с версиями бэкендов,
парами «правило — цель», которые бэкенд не поддерживает, и известными расхождениями в движках.
Конвейер pipelines/scii-telemetry.yml добавляет к условию отбор по event.dataset: запрос ищет
только в событиях своего источника, даже если гейт и устройства пишут в один индекс. Файлы
запросов не правятся вручную: CI пересобирает их с --check и падает, если они разошлись с правилами.

usage: python -m tools.convert [--check]
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from importlib.metadata import version

from sigma.backends.elasticsearch import EqlBackend, ESQLBackend, LuceneBackend
from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.backends.splunk import SplunkBackend
from sigma.exceptions import SigmaError

from .common import CONVERSIONS, load_rule_file, pipeline, rule_files
from .known_issues import KNOWN


@dataclass(frozen=True)
class Target:
    name: str
    title: str
    backend: type
    package: str
    ext: str
    engine: str | None  # где запрос исполняется в CI (tools.siem_it)


TARGETS = (
    Target("opensearch", "OpenSearch, Lucene (query_string)", OpensearchLuceneBackend,
           "pySigma-backend-opensearch", "lucene", "OpenSearch 3.8.0"),
    Target("elasticsearch", "Elasticsearch, Lucene (query_string)", LuceneBackend,
           "pySigma-backend-elasticsearch", "lucene", "Elasticsearch 9.5.5"),
    Target("elasticsearch-eql", "Elasticsearch, EQL", EqlBackend,
           "pySigma-backend-elasticsearch", "eql", "Elasticsearch 9.5.5"),
    Target("elasticsearch-esql", "Elasticsearch, ES\\|QL", ESQLBackend,
           "pySigma-backend-elasticsearch", "esql", "Elasticsearch 9.5.5"),
    Target("splunk", "Splunk, SPL", SplunkBackend, "pySigma-backend-splunk", "spl", None),
)


def build() -> dict[str, str]:
    """Относительный путь в conversions/ → содержимое файла."""
    files: dict[str, str] = {}
    unsupported: list[tuple[str, str, str]] = []
    rfs = rule_files()
    counts = {t.name: 0 for t in TARGETS}
    for rf in rfs:
        for target in TARGETS:
            collection = load_rule_file(rf.path).collection  # конвейер меняет правила: каждой цели — свои
            try:
                queries = target.backend(processing_pipeline=pipeline()).convert(collection)
            except (SigmaError, NotImplementedError) as exc:
                unsupported.append((rf.key, target.name, str(exc).split(" (")[0]))
                continue
            files[f"{target.name}/{rf.key}.{target.ext}"] = "\n\n".join(str(q).strip() for q in queries) + "\n"
            counts[target.name] += 1

    lines = [
        "# Запросы для SIEM",
        "",
        "Сгенерированы `python -m tools.convert` из правил [`rules/`](../rules/) с конвейером",
        "[`pipelines/scii-telemetry.yml`](../pipelines/scii-telemetry.yml): к условию каждого правила",
        "добавлен отбор `event.dataset` его источника. Вручную не правятся; CI проверяет, что запросы",
        "совпадают с правилами (`python -m tools.convert --check`).",
        "",
        "| Цель | Бэкенд | Версия | Запросов | Исполняется в CI |",
        "|---|---|---|---|---|",
    ]
    for t in TARGETS:
        lines.append(f"| `{t.name}/` — {t.title} | {t.package} | {version(t.package)} | "
                     f"{counts[t.name]} из {len(rfs)} | {t.engine or 'нет'} |")
    lines += ["", f"pySigma {version('pySigma')}.", ""]
    if unsupported:
        lines += ["## Не поддерживается бэкендом", "", "| Правило | Цель | Сообщение бэкенда |", "|---|---|---|"]
        lines += [f"| `{key}` | `{target}` | {msg} |" for key, target, msg in unsupported]
        lines.append("")
    lines += [
        "## Проверка в движках",
        "",
        "`python -m tools.siem_it` загружает наборы событий [`dataset/`](../dataset/) и синтетическое",
        "событие в OpenSearch и Elasticsearch и исполняет запросы `opensearch/`, `elasticsearch/`,",
        "`elasticsearch-eql/` и `elasticsearch-esql/`: найденные события (для корреляций — группы)",
        "должны совпасть с матрицей обнаружения стенда [`tools/harness.py`](../tools/harness.py).",
        "Запросы `splunk/` в Splunk не исполнялись. Известные расхождения:",
        "",
        "| Правило | Цель | Причина | Правка, с которой запрос проходит |",
        "|---|---|---|---|",
    ]
    for k in KNOWN:
        fix = "; ".join(f"`{old.strip()}` → `{new.strip()}`" if new.strip() else f"удалить `{old.strip()}`"
                        for old, new in k.fix) or "—"
        lines.append(f"| `{k.rule}` | `{k.target}` | {k.reason.replace('|', chr(92) + '|')} | {fix} |")
    lines += [
        "",
        "Окна корреляций бэкенды переводят по-разному (EQL — `maxspan` последовательности, ES|QL и",
        "SPL — фиксированные корзины времени) — см. [`docs/siem.md`](../docs/siem.md).",
        "",
    ]
    files["README.md"] = "\n".join(lines)
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="сверить с файлами, ничего не записывая")
    args = parser.parse_args(argv)
    files = build()
    existing = {p.relative_to(CONVERSIONS).as_posix() for p in CONVERSIONS.rglob("*") if p.is_file()}
    if args.check:
        stale = sorted(
            [rel for rel, text in files.items()
             if not (CONVERSIONS / rel).is_file() or (CONVERSIONS / rel).read_text(encoding="utf-8") != text]
            + sorted(existing - files.keys())
        )
        for rel in stale:
            print(f"расходится: conversions/{rel}")
        print(f"файлов: {len(files)}, расхождений: {len(stale)}")
        return 1 if stale else 0
    for rel in existing - files.keys():
        (CONVERSIONS / rel).unlink()
    for rel, text in files.items():
        path = CONVERSIONS / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    print(f"записано файлов: {len(files)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

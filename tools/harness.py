"""Стенд: правила на событиях телеметрии.

Условия правил исполняются SQL-запросами, которые строит бэкенд pySigma для SQLite с конвейером
полей репозитория (pipelines/scii-telemetry.yml), — проверяется и правило, и его конвертация.
Столбцы таблицы — поля событий через точку (event.action), с COLLATE NOCASE: строки в Sigma
сравниваются без учёта регистра. Корреляции event_count, temporal и temporal_ordered вычисляются
здесь по спецификации Sigma со скользящим окном.
"""

from __future__ import annotations

import json
import operator
import re
import sqlite3
from datetime import datetime

from sigma.backends.sqlite import sqliteBackend
from sigma.correlations import SigmaCorrelationRule, SigmaCorrelationType
from sigma.rule import SigmaRule

from .common import flatten, get, pipeline, strip_test

TABLE = "logs"


def _sql_value(value):
    if isinstance(value, bool):
        return int(value)
    if value is None or isinstance(value, (int, float, str)):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _ms(timestamp: str) -> int:
    return int(datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp() * 1000)


def rule_sql(rule: SigmaRule) -> str:
    """Запрос SQLite для правила, в том числе базового правила корреляции (как отдельного правила).

    Конвертируется копия: конвейер дописывает условие на event.dataset в само правило, и повторная
    конвертация того же объекта добавила бы его снова. Копия базового правила корреляции — обычное
    правило: бэкенд не выдаёт запрос для правила, на которое ссылается корреляция.
    """
    rule = SigmaRule.from_dict(rule.to_dict())
    queries = sqliteBackend(processing_pipeline=pipeline()).convert_rule(rule)
    if len(queries) != 1:
        raise ValueError(f"{rule.title}: ожидался один запрос, получено {len(queries)}")
    return queries[0].replace("<TABLE_NAME>", TABLE)


class Harness:
    """События в таблице SQLite в памяти; номер события — его индекс во входном списке."""

    def __init__(self, events: list[dict]):
        self.events = [strip_test(e) for e in events]
        flat = [flatten(e) for e in self.events]
        self.db = sqlite3.connect(":memory:")
        self.columns: list[str] = []
        for row in flat:
            for key in row:
                if key not in self.columns:
                    self.columns.append(key)
        defs = ", ".join(['"_eid" INTEGER PRIMARY KEY'] + [f'"{c}" COLLATE NOCASE' for c in self.columns])
        self.db.execute(f"CREATE TABLE {TABLE} ({defs})")
        for eid, row in enumerate(flat):
            cols = ['"_eid"'] + [f'"{k}"' for k in row]
            self.db.execute(f"INSERT INTO {TABLE} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                            [eid] + [_sql_value(v) for v in row.values()])

    def _run(self, sql: str) -> list[int]:
        while True:
            try:
                cursor = self.db.execute(sql)
                break
            except sqlite3.OperationalError as exc:
                missing = re.fullmatch(r"no such column: (.+)", str(exc))
                if not missing:
                    raise
                self.db.execute(f'ALTER TABLE {TABLE} ADD COLUMN "{missing.group(1)}" COLLATE NOCASE')
        names = [d[0] for d in cursor.description]
        index = names.index("_eid")
        return sorted(row[index] for row in cursor.fetchall())

    def match(self, rule: SigmaRule) -> list[int]:
        return self._run(rule_sql(rule))

    def correlate(self, corr: SigmaCorrelationRule) -> dict[tuple, set[int]]:
        """Срабатывания корреляции: ключ группы → события, которыми завершаются цепочки или окна."""
        group_by = list(corr.group_by or [])
        span = corr.timespan.seconds * 1000
        steps = [ref.rule for ref in corr.rules]
        items: dict[tuple, list[tuple[int, int, int]]] = {}
        for step, rule in enumerate(steps):
            for eid in self.match(rule):
                ev = self.events[eid]
                key = tuple(get(ev, f) for f in group_by)
                items.setdefault(key, []).append((_ms(ev["@timestamp"]), eid, step))
        fired: dict[tuple, set[int]] = {}
        for key, seq in items.items():
            seq.sort()
            if corr.type == SigmaCorrelationType.TEMPORAL_ORDERED:
                hits = _ordered(seq, len(steps), span)
            elif corr.type == SigmaCorrelationType.TEMPORAL:
                hits = _unordered(seq, len(steps), span)
            elif corr.type == SigmaCorrelationType.EVENT_COUNT:
                hits = _count(seq, span, corr.condition)
            else:
                raise NotImplementedError(f"тип корреляции {corr.type.name} не поддерживается")
            if hits:
                fired[key] = hits
        return fired


def _ordered(seq, steps, span):
    """События последнего шага, для которых есть цепочка шагов 0..n-1 по порядку журнала в окне."""
    hits = set()
    for i, (t_end, eid_end, step_end) in enumerate(seq):
        if step_end != steps - 1:
            continue
        # с конца: для каждого предыдущего шага — самое позднее подходящее событие раньше текущего
        want, cursor_t, ok = steps - 2, t_end, True
        for t, eid, step in reversed(seq[:i]):
            if want < 0:
                break
            if t_end - t > span:
                ok = False
                break
            if step == want and t <= cursor_t:
                want -= 1
                cursor_t = t
        if ok and want < 0:
            hits.add(eid_end)
    return hits


def _unordered(seq, steps, span):
    """События, на которых в окне [t - span, t] впервые собраны все шаги."""
    hits = set()
    for i, (t_end, eid_end, _step) in enumerate(seq):
        seen = {s for t, _e, s in seq[: i + 1] if t_end - t <= span}
        if len(seen) == steps:
            hits.add(eid_end)
    return hits


_OPS = {"LT": operator.lt, "LTE": operator.le, "GT": operator.gt, "GTE": operator.ge,
        "EQ": operator.eq, "NEQ": operator.ne}


def _count(seq, span, condition):
    """События, на которых число событий группы в окне [t - span, t] удовлетворяет условию."""
    hits = set()
    holds = _OPS[condition.op.name]
    for i, (t_end, eid_end, _step) in enumerate(seq):
        n = sum(1 for t, _e, _s in seq[: i + 1] if t_end - t <= span)
        if holds(n, condition.count):
            hits.add(eid_end)
    return hits

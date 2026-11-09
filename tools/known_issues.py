"""Известные расхождения запросов из conversions/ с матрицей стенда в движках SIEM.

Каждая запись найдена прогоном tools.siem_it и объяснена. Проверка не падает на таких случаях,
но падает, если случай неожиданно прошёл: тогда запись устарела (например, исправлен бэкенд).
Для дефектов бэкенда заданы правки запроса (заменить подстроку): исправленный запрос обязан
найти то же, что стенд, — так в CI подтверждается, что дефект именно в этих местах.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Known:
    target: str  # каталог conversions/
    rule: str
    reason: str
    fix: tuple[tuple[str, str], ...] = ()

    def apply(self, query: str) -> str | None:
        """Запрос с правками; None, если какой-то подстроки в запросе нет."""
        for old, new in self.fix:
            if old not in query:
                return None
            query = query.replace(old, new)
        return query


_EQL_COLON = (
    "бэкенд EQL сравнивает логическое или числовое поле оператором «:», а Elasticsearch принимает «:» "
    "только для строк и предлагает «==» (HTTP 400)"
)
_EQL_SEQUENCE = (
    "бэкенд EQL дописывает к последовательности temporal_ordered «by  with runs=2» с пустым полем, и "
    "запрос не разбирается (HTTP 400); кроме того, номер решения гейта сравнивается через «:»"
)

_ESQL_BUCKETS = (
    "ES|QL-запрос бэкенда считает события в фиксированных 10-минутных корзинах (date_trunc), а не в "
    "скользящем окне Sigma: три отказа за 4,5 минуты через границу корзины (синтетические события S2) "
    "делятся на 1 и 2 и не находятся; отказы случая C7 попадают в одну корзину и находятся"
)

KNOWN: tuple[Known, ...] = (
    Known("elasticsearch-eql", "scii_device_installed_image_not_admitted", _EQL_COLON,
          (("scii.reconcile.admitted:false", "scii.reconcile.admitted == false"),)),
    Known("elasticsearch-eql", "scii_gate_evidence_requested", _EQL_COLON,
          (("scii.gate.code:20", "scii.gate.code == 20"),)),
    Known("elasticsearch-eql", "scii_gate_release_rejected", _EQL_COLON,
          (("scii.gate.code:30", "scii.gate.code == 30"),)),
    Known("elasticsearch-eql", "scii_gate_veto", _EQL_COLON,
          (("scii.gate.veto:true", "scii.gate.veto == true"),)),
    Known("elasticsearch-eql", "scii_rejected_release_installed", _EQL_SEQUENCE,
          ((" by  with runs=2", ""), ("scii.gate.code:30", "scii.gate.code == 30"))),
    Known("elasticsearch-esql", "scii_device_management_auth_failures", _ESQL_BUCKETS),
)


def lookup(target: str, rule: str) -> Known | None:
    for k in KNOWN:
        if (k.target, k.rule) == (target, rule):
            return k
    return None

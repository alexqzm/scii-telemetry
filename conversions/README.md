# Запросы для SIEM

Сгенерированы `python -m tools.convert` из правил [`rules/`](../rules/) с конвейером
[`pipelines/scii-telemetry.yml`](../pipelines/scii-telemetry.yml): к условию каждого правила
добавлен отбор `event.dataset` его источника. Вручную не правятся; CI проверяет, что запросы
совпадают с правилами (`python -m tools.convert --check`).

| Цель | Бэкенд | Версия | Запросов | Исполняется в CI |
|---|---|---|---|---|
| `opensearch/` — OpenSearch, Lucene (query_string) | pySigma-backend-opensearch | 2.0.3 | 17 из 19 | OpenSearch 3.8.0 |
| `elasticsearch/` — Elasticsearch, Lucene (query_string) | pySigma-backend-elasticsearch | 2.1.1 | 17 из 19 | Elasticsearch 9.5.5 |
| `elasticsearch-eql/` — Elasticsearch, EQL | pySigma-backend-elasticsearch | 2.1.1 | 19 из 19 | Elasticsearch 9.5.5 |
| `elasticsearch-esql/` — Elasticsearch, ES\|QL | pySigma-backend-elasticsearch | 2.1.1 | 18 из 19 | Elasticsearch 9.5.5 |
| `splunk/` — Splunk, SPL | pySigma-backend-splunk | 2.1.0 | 18 из 19 | нет |

pySigma 1.5.1.

## Не поддерживается бэкендом

| Правило | Цель | Сообщение бэкенда |
|---|---|---|
| `scii_device_management_auth_failures` | `opensearch` | Backend does not support correlation rules. |
| `scii_device_management_auth_failures` | `elasticsearch` | Backend does not support correlation rules. |
| `scii_rejected_release_installed` | `opensearch` | Backend does not support correlation rules. |
| `scii_rejected_release_installed` | `elasticsearch` | Backend does not support correlation rules. |
| `scii_rejected_release_installed` | `elasticsearch-esql` | Correlation type 'temporal_ordered' is not supported by backend. |
| `scii_rejected_release_installed` | `splunk` | Correlation type 'temporal_ordered' is not supported by backend. |

## Проверка в движках

`python -m tools.siem_it` загружает наборы событий [`dataset/`](../dataset/) и синтетическое
событие в OpenSearch и Elasticsearch и исполняет запросы `opensearch/`, `elasticsearch/`,
`elasticsearch-eql/` и `elasticsearch-esql/`: найденные события (для корреляций — группы)
должны совпасть с матрицей обнаружения стенда [`tools/harness.py`](../tools/harness.py).
Запросы `splunk/` в Splunk не исполнялись. Известные расхождения:

| Правило | Цель | Причина | Правка, с которой запрос проходит |
|---|---|---|---|
| `scii_device_installed_image_not_admitted` | `elasticsearch-eql` | бэкенд EQL сравнивает логическое или числовое поле оператором «:», а Elasticsearch принимает «:» только для строк и предлагает «==» (HTTP 400) | `scii.reconcile.admitted:false` → `scii.reconcile.admitted == false` |
| `scii_gate_evidence_requested` | `elasticsearch-eql` | бэкенд EQL сравнивает логическое или числовое поле оператором «:», а Elasticsearch принимает «:» только для строк и предлагает «==» (HTTP 400) | `scii.gate.code:20` → `scii.gate.code == 20` |
| `scii_gate_release_rejected` | `elasticsearch-eql` | бэкенд EQL сравнивает логическое или числовое поле оператором «:», а Elasticsearch принимает «:» только для строк и предлагает «==» (HTTP 400) | `scii.gate.code:30` → `scii.gate.code == 30` |
| `scii_gate_veto` | `elasticsearch-eql` | бэкенд EQL сравнивает логическое или числовое поле оператором «:», а Elasticsearch принимает «:» только для строк и предлагает «==» (HTTP 400) | `scii.gate.veto:true` → `scii.gate.veto == true` |
| `scii_rejected_release_installed` | `elasticsearch-eql` | бэкенд EQL дописывает к последовательности temporal_ordered «by  with runs=2» с пустым полем, и запрос не разбирается (HTTP 400); кроме того, номер решения гейта сравнивается через «:» | удалить `by  with runs=2`; `scii.gate.code:30` → `scii.gate.code == 30` |
| `scii_device_management_auth_failures` | `elasticsearch-esql` | ES\|QL-запрос бэкенда считает события в фиксированных 10-минутных корзинах (date_trunc), а не в скользящем окне Sigma: три отказа за 4,5 минуты через границу корзины (синтетические события S2) делятся на 1 и 2 и не находятся; отказы случая C7 попадают в одну корзину и находятся | — |

Окна корреляций бэкенды переводят по-разному (EQL — `maxspan` последовательности, ES|QL и
SPL — фиксированные корзины времени) — см. [`docs/siem.md`](../docs/siem.md).

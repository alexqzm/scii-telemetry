# Телеметрия в SIEM

Запросы в [`conversions/`](../conversions/) собраны официальными бэкендами pySigma с конвейером
[`pipelines/scii-telemetry.yml`](../pipelines/scii-telemetry.yml): к условию каждого правила
добавлен отбор `event.dataset` его источника (`scii.gate` или `scii.device`), а запросы ES|QL
читают индексы `scii-*`. Запросам нужны 15 полей: `event.dataset`, `event.action`,
`event.outcome`, `event.reason`, `file.hash.sha256`, `host.name`, `scii.device.path`,
`scii.device.svn_change`, `scii.evidence.id`, `scii.evidence.state`, `scii.gate.code`,
`scii.gate.veto`, `scii.mgmt.command`, `scii.reconcile.admitted`, `scii.report.signature`.

## OpenSearch и Elasticsearch

```bash
# шаблон индекса по схеме событий: строки — keyword, @timestamp — date, dynamic: strict
curl -X PUT localhost:9200/_index_template/scii-telemetry \
  -H 'Content-Type: application/json' --data-binary @schema/index-template.json

# загрузка набора (_id — event.id)
python -m sciitel bulk dataset/cpslab-0.1.0/events.jsonl --index scii-cpslab > bulk.ndjson
curl -X POST 'localhost:9200/_bulk?refresh=true' \
  -H 'Content-Type: application/x-ndjson' --data-binary @bulk.ndjson
```

- **Lucene** (`opensearch/*.lucene`, `elasticsearch/*.lucene`) — строка поиска Discover или
  запрос `query_string`.
- **EQL** (`elasticsearch-eql/*.eql`) — `POST scii-*/_eql/search`. Отчёты устройства датированы
  с точностью до секунды, поэтому последовательностям из отчётов одного устройства (корреляция
  `scii_device_management_auth_failures`, группировка по `host.name`) нужен
  `"tiebreaker_field": "event.sequence"` — номер отчёта устройства; без него три отказа одной
  секунды не образуют последовательность. Для последовательности «решение гейта → установка»
  общего счётчика нет, и `tiebreaker_field` ей не задаётся.
- **ES|QL** (`elasticsearch-esql/*.esql`) — `POST _query`; запрос читает `from scii-*`.

Без шаблона индекса запросы EQL и ES|QL падают на полях, которых нет в загруженных событиях
(«Unknown column»): например, в наборе без установок нет `scii.device.svn_change`. Шаблон
сопоставляет все поля схемы заранее.

### Что проверено

CI (задание `siem`) поднимает OpenSearch 3.8.0 и Elasticsearch 9.5.5 (образы закреплены по
дайджесту), ставит шаблон индекса, по очереди загружает наборы `cpslab-0.1.0`, `cases-0.1.0`,
`ardupilot-0.1.0` и синтетические события и исполняет запросы (`python -m tools.siem_it`). Найденные события должны
совпасть с теми, на которых правило срабатывает в стенде [`tools/harness.py`](../tools/harness.py);
для корреляций сравниваются группы.

| Движок | Язык | Запросов | Совпало со стендом | Известные расхождения |
|---|---|---|---|---|
| OpenSearch 3.8.0 | Lucene | 17 | 17 | — |
| Elasticsearch 9.5.5 | Lucene | 17 | 17 | — |
| Elasticsearch 9.5.5 | EQL | 19 | 14 | 5 — дефекты бэкенда; запросы с правкой проходят |
| Elasticsearch 9.5.5 | ES\|QL | 18 | 17 | 1 — окно корреляции |

Дефекты бэкенда EQL (pySigma-backend-elasticsearch 2.1.1):

- логическое и числовое поле сравнивается оператором `:` (`scii.gate.veto:true`,
  `scii.gate.code:30`), а Elasticsearch принимает `:` только для строк — HTTP 400; с `==` запросы
  находят то же, что стенд;
- к последовательности `temporal_ordered` дописывается `by  with runs=2` с пустым полем — запрос
  не разбирается; без этого хвоста (и с `==` для номера решения) находит те же группы, что стенд.

Список с причинами и правками — в [`tools/known_issues.py`](../tools/known_issues.py) и
[`conversions/README.md`](../conversions/README.md). Проверка падает и на неожиданном успехе:
когда бэкенд исправят, запись придётся убрать.

## Окна корреляций

| Правило | Sigma (стенд) | EQL | ES\|QL | SPL |
|---|---|---|---|---|
| `scii_rejected_release_installed`: решение «отказ», затем установка того же образа за 30 суток | порядок событий и скользящее окно | `sequence by file.hash.sha256 with maxspan=30d` (после правки) | бэкенд не поддерживает `temporal_ordered` | бэкенд не поддерживает `temporal_ordered` |
| `scii_device_management_auth_failures`: три отказа DENIED за 10 минут | скользящее окно | `sequence … with runs=3`, `maxspan=10m`, нужен `tiebreaker_field` | фиксированные корзины `date_trunc(10minutes, @timestamp)` | фиксированные корзины `bin _time span=10m` |

Фиксированные корзины теряют серии через границу корзины. Синтетические события S2 — три отказа
за 4,5 минуты через 12:00 — стенд и EQL находят, а ES|QL нет (известное расхождение); события
S3 — отказы с промежутками 10,5 минуты — не находит никто. Запрос SPL устроен так же, как ES|QL,
но в Splunk не исполнялся.

В наборе стенда решения гейта и установки попадают в одну секунду. Стенд считает решение
гейта более ранним, как оно и записано; EQL без `tiebreaker_field` упорядочивает события одной
секунды по порядку индексации (решения загружаются первыми). В эксплуатации между решением гейта
и установкой проходят часы и дни.

## Splunk

Запросы `splunk/*.spl` получены бэкендом pySigma-backend-splunk 2.1.0 и в Splunk не исполнялись.
Они ожидают поля с именами через точку (`event.action`, `scii.gate.code`) — так их называет
извлечение полей из JSON. Корреляция `temporal_ordered` бэкендом не поддерживается.

## KUMA

Бэкенда pySigma для KUMA в PyPI нет (`pysigma-backend-kuma` не найден 09.11.2026), поэтому
запросов KUMA в `conversions/` нет, и в KUMA правила не проверялись. Правила Sigma KUMA переводит
своим конвертером со словарём полей; чтобы правила этого репозитория работали в KUMA, нужен
нормализатор JSON для событий схемы 1, который раскладывает 15 перечисленных выше полей по полям
события KUMA, и тот же словарь в конвертере. Как это сделано для журнала аудита GitHub — в
[cicd-sigma-rules/docs/kuma.md](https://github.com/alexqzm/cicd-sigma-rules/blob/main/docs/kuma.md).

# Схема событий

Схема 1: [`schema/scii-event.schema.json`](../schema/scii-event.schema.json) (JSON Schema 2020-12),
шаблон индекса OpenSearch и Elasticsearch — [`schema/index-template.json`](../schema/index-template.json)
(`python -m sciitel index-template` строит его из схемы, тест сверяет). Поля ECS — там, где
есть подходящие: `@timestamp`, `event.*`, `host.name`, `file.hash.sha256`, `package.*`,
`observer.*`, `labels`; решения гейта, свидетельства и отчёты устройств — в расширении `scii.*`.
Проверка набора: `python -m sciitel validate events.jsonl`.

## Источники

| `event.dataset` | `event.action` | Откуда | Когда |
|---|---|---|---|
| `scii.gate` | `gate-decision` | запись журнала гейта `gate/ledger.jsonl` и отчёт scii-gate `report.json` | решение по выпуску |
| `scii.gate` | `gate-evidence` | состояние свидетельства в том же отчёте | по событию на каждое из 17 свидетельств профиля |
| `scii.device` | `device-factory` | подписанный отчёт устройства | ввод в эксплуатацию с исходным образом |
| `scii.device` | `device-install` | то же | образ установлен |
| `scii.device` | `device-reject` | то же | образ отвергнут (код в `event.reason`) |
| `scii.device` | `device-mgmt` | то же | команда по каналу управления (выполнена или отвергнута) |

`event.outcome` у гейта — исход самой проверки (`success`); решение — в `event.reason`
(`admit`, `review`, `request`, `reject`) и `scii.gate.code` (0, 10, 20, 30). У устройства
`event.outcome` — принято ли действие (`success`) или отвергнуто (`failure`).

## Поля

| Поле | Тип | Источник | Значение |
|---|---|---|---|
| `@timestamp` | дата, UTC, секунды | оба | время решения гейта или отчёта устройства |
| `event.id` | строка | оба | `gate-<номер решения>`, `gate-<номер>-<свидетельство>`, `<устройство>-<номер отчёта>` |
| `event.sequence` | целое | устройство | номер отчёта устройства; упорядочивает отчёты одной секунды |
| `event.reason` | строка | оба | решение гейта или код исхода на устройстве (таблица ниже) |
| `file.hash.sha256` | строка | оба | SHA-256 образа выпуска (гейт) или образа, который пытались установить (устройство) |
| `package.name`, `package.version` | строки | оба | изделие и версия выпуска |
| `host.name` | строка | устройство | имя устройства |
| `observer.product` | строка | оба | `scii-gate` или `device-report`; `observer.version` — версия scii-gate |
| `scii.gate.serial`, `.variant`, `.device_class` | целое, строка, целое | гейт | номер решения в журнале, вариант выпуска, класс устройства парка |
| `scii.gate.code`, `.decision` | целое, строка | решение | 0 допуск, 10 ручное рассмотрение, 20 запрос свидетельств, 30 отказ |
| `scii.gate.veto` | логическое | решение | блокирующее условие G = 0: опровергнуто свидетельство обязательной стадии |
| `scii.gate.complete` | логическое | решение | бинарный контроль B = 1: нет опровергнутых, обязательные предъявлены |
| `scii.gate.r_min`, `.r_max`, `.theta` | дробные | решение | границы интервала индекса целостности и порог политики |
| `scii.evidence.id`, `.name`, `.stage`, `.stage_name` | строки | свидетельство | свидетельство профиля (s11–s54) и его стадия (v1–v5) |
| `scii.evidence.mandatory`, `.stage_mandatory` | логические | свидетельство | обязательно ли свидетельство и его стадия |
| `scii.evidence.state` | строка | свидетельство | `confirmed`, `missing` или `refuted` |
| `scii.evidence.reason` | строка | свидетельство | пояснение scii-gate (изменчивое: номера ключей и коммитов) |
| `scii.device.class`, `.instance` | целое, строка | устройство | класс и экземпляр устройства |
| `scii.device.level`, `.enforcement` | целое, строка | устройство | уровень защиты стенда: 0 `none`, 1 `vendor_signature`, 2 `scii_receipt` |
| `scii.device.path` | строка | устройство | `factory`, `update` (канал обновления), `ews` (инженерная станция), `mgmt` |
| `scii.device.installed.sha256`, `.version`, `.svn` | строка, строка, целое | устройство | что установлено после события |
| `scii.device.svn_previous`, `.svn_change` | целое, строка | установка | номер версии до установки и изменение: `increase`, `same`, `decrease` |
| `scii.report.signature` | строка | устройство | `valid` или `invalid`: проверка подписи отчёта ключом устройства |
| `scii.reconcile.admitted` | логическое | установка, ввод | допущен ли установленный образ гейтом для класса устройства |
| `scii.mgmt.command` | строка | команда | `stop`, `start`, `factory-reset` |
| `labels.cpslab_run`, `_scenario`, `_level` | строки | устройство | метки стенда; в эксплуатации их нет |

Три поля выгрузка вычисляет сама — в отчёте устройства их нет, а правилам они нужны:

- `scii.report.signature` — подпись Ed25519 над каноническим JSON отчёта проверяется открытым
  ключом устройства (`device.pk`);
- `scii.reconcile.admitted` — пара (класс устройства, SHA-256 установленного образа) ищется среди
  допусков журнала гейта, как это делает монитор стенда;
- `scii.device.svn_change` — номер версии установленного образа сравнивается с предыдущим отчётом
  того же устройства.

Сверка и изменение версии вычисляются только для отчётов с действительной подписью: содержимое
поддельного отчёта не должно ни поднимать, ни гасить тревоги (случай C8 в [`matrix.md`](matrix.md)).

## Коды исхода на устройстве

| Код | Кто выдаёт | Значение |
|---|---|---|
| `OK` | устройство | принято |
| `NO_UPDATE` | устройство | новых обновлений нет |
| `IMAGE_FORMAT` | устройство | образ не разбирается |
| `BOOT_SIG` | загрузчик (уровень L1 и выше) | подпись образа не принимается ключом поставщика |
| `DENIED` | канал управления | неверный пароль управления |
| `UNKNOWN_COMMAND` | канал управления | неизвестная команда |
| `NO_RECEIPT` | scii-agent (L2) | нет квитанции допуска |
| `FORMAT` | scii-agent | квитанция не разбирается |
| `KEY` | scii-agent | неизвестный ключ гейта или ключ вне эпохи |
| `SIGNATURE` | scii-agent | подпись квитанции неверна |
| `DECISION` | scii-agent | квитанция не о допуске |
| `TARGET` | scii-agent | квитанция для другого класса или экземпляра устройства |
| `POLICY` | scii-agent | квитанция по другой политике или устаревшей эпохе |
| `ROLLBACK` | scii-agent | номер версии в квитанции ниже установленного |
| `SIZE` | scii-agent | длина образа не совпадает с квитанцией |
| `DIGEST` | scii-agent | дайджест образа не совпадает с квитанцией |
| `STATE` | устройство с A/B-копиями состояния | нет действительной копии состояния антиотката |

Проверки scii-agent идут в порядке таблицы (NO_RECEIPT … DIGEST), код даёт первая непройденная —
см. [scii-verify](https://github.com/alexqzm/scii-verify).

## Примеры

Решение гейта по выпуску из заражённой сборочной среды (набор `cpslab-0.1.0`):

```json
{"@timestamp": "2026-11-09T11:38:40Z",
 "event": {"id": "gate-0005", "kind": "event", "module": "scii", "dataset": "scii.gate",
           "category": ["package"], "type": ["info"], "action": "gate-decision", "outcome": "success",
           "reason": "reject"},
 "file": {"hash": {"sha256": "56abaccf8405cf25e9df5e60152861fa7574becd8116b39be070339848f5c7a3"}},
 "package": {"name": "tank-controller", "version": "1.1.0"},
 "observer": {"vendor": "SCII", "product": "scii-gate", "version": "0.1.5"},
 "scii": {"schema": "1",
          "gate": {"serial": 5, "variant": "tank-1.1.0-compromised-build", "device_class": 7001,
                   "code": 30, "decision": "reject", "veto": true, "complete": false,
                   "r_min": 0.18, "r_max": 0.54, "theta": 0.9}}}
```

Отказ устройства L2 в сценарии A1 — образ на сервере обновлений подменён, квитанция подлинная:

```json
{"@timestamp": "2026-11-09T11:38:41Z",
 "event": {"id": "plc-A1-L2-0002", "kind": "event", "module": "scii", "dataset": "scii.device",
           "category": ["package"], "type": ["installation"], "action": "device-reject",
           "outcome": "failure", "reason": "DIGEST", "sequence": 2},
 "file": {"hash": {"sha256": "56abaccf8405cf25e9df5e60152861fa7574becd8116b39be070339848f5c7a3"}},
 "host": {"name": "plc-A1-L2"},
 "observer": {"vendor": "SCII", "product": "device-report", "name": "plc-A1-L2"},
 "labels": {"cpslab_run": "A1-L2", "cpslab_scenario": "A1", "cpslab_level": "2"},
 "scii": {"schema": "1",
          "device": {"class": 7001, "instance": "00000000000000000000000000000000", "level": 2,
                     "enforcement": "scii_receipt", "path": "update",
                     "installed": {"sha256": "c7fe7ab9317f02cd95d10d2f33235079d71a0ce4954369cfc54fab139eab2820",
                                   "version": "1.0.0", "svn": 4294967551}},
          "report": {"signature": "valid"}}}
```

## Изменчивые поля

От прогона к прогону стенда меняются `@timestamp` и `scii.evidence.reason` (стенд заново создаёт
ключи ролей, а их номера и подписи коммитов попадают в пояснения). `python -m sciitel compare`
сравнивает наборы без этих полей; CI так сверяет свежий прогон стенда с наборами `dataset/`.

# Правила

Сгенерировано `python -m tools.matrix --write` из [`rules/`](../rules/) и
[`mappings/mappings.yml`](../mappings/mappings.yml). Уровень и техники ATT&CK — из правил
(для корреляции — из правила корреляции; базовые правила корреляций — информационные).
Где правило срабатывает — в [`matrix.md`](matrix.md).

| Правило | Источник | Уровень | ATT&CK | Что означает |
|---|---|---|---|---|
| [`scii_device_boot_signature_rejected`](../rules/scii/device/scii_device_boot_signature_rejected.yml) | устройство | высокий | T0862, T1693.001 | загрузчик отверг образ, подпись поставщика над которым не проверяется |
| [`scii_device_image_digest_mismatch`](../rules/scii/device/scii_device_image_digest_mismatch.yml) | устройство | высокий | T0862, T1693.001 | квитанция подлинная, но длина (SIZE) или дайджест (DIGEST) образа другие |
| [`scii_device_receipt_rejected`](../rules/scii/device/scii_device_receipt_rejected.yml) | устройство | высокий | T0862, T1693.001 | квитанция не разбирается, подписана чужим ключом, изменена, выдана под другую политику или не о допуске |
| [`scii_device_update_without_receipt`](../rules/scii/device/scii_device_update_without_receipt.yml) | устройство | высокий | T0862, T1195.002 | образ пришёл по каналу обновления без квитанции гейта (NO_RECEIPT) |
| [`scii_device_program_download_without_receipt`](../rules/scii/device/scii_device_program_download_without_receipt.yml) | устройство | высокий | T0843, T0889 | программа с инженерной станции без квитанции гейта (NO_RECEIPT на пути ews) |
| [`scii_device_rollback_blocked`](../rules/scii/device/scii_device_rollback_blocked.yml) | устройство | высокий | T1689, T1693.001 | номер версии в квитанции ниже установленного |
| [`scii_device_wrong_target`](../rules/scii/device/scii_device_wrong_target.yml) | устройство | средний | T1693.001 | квитанция выдана для другого класса или экземпляра устройства |
| [`scii_device_state_invalid`](../rules/scii/device/scii_device_state_invalid.yml) | устройство | высокий | T1693.001 | у устройства нет действительной копии состояния антиотката |
| [`scii_device_installed_image_not_admitted`](../rules/scii/device/scii_device_installed_image_not_admitted.yml) | устройство | высокий | T0862, T1693.001 | установлен образ, которого нет среди допущенных гейтом для этого класса устройства (сверка с журналом гейта) |
| [`scii_device_version_decreased`](../rules/scii/device/scii_device_version_decreased.yml) | устройство | высокий | T1689, T1693.001 | установлен образ с номером версии ниже прежнего |
| [`scii_device_report_signature_invalid`](../rules/scii/device/scii_device_report_signature_invalid.yml) | устройство | высокий | T1692.002 | подпись отчёта устройства не проверяется его ключом |
| [`scii_device_management_command_accepted`](../rules/scii/device/scii_device_management_command_accepted.yml) | устройство | средний | T0859, T0813 | контроллер выполнил команду stop или factory-reset по каналу управления |
| [`scii_gate_veto`](../rules/scii/gate/scii_gate_veto.yml) | гейт | высокий | T0862, T1195.002 | опровергнуто свидетельство обязательной стадии |
| [`scii_gate_release_rejected`](../rules/scii/gate/scii_gate_release_rejected.yml) | гейт | средний | T0862, T1195.002 | решение гейта «отказ» (вето или верхняя граница индекса ниже порога) |
| [`scii_gate_evidence_requested`](../rules/scii/gate/scii_gate_evidence_requested.yml) | гейт | низкий | T0862 | не предъявлено обязательное свидетельство, гейт запрашивает его |
| [`scii_gate_rebuild_mismatch`](../rules/scii/gate/scii_gate_rebuild_mismatch.yml) | гейт | высокий | T1195.002, T0862 | независимая пересборка из заявленного источника дала другой образ |
| [`scii_gate_source_signature_refuted`](../rules/scii/gate/scii_gate_source_signature_refuted.yml) | гейт | высокий | T1195.002, T0862 | подписи коммитов или тега выпуска не проверяются доверенными ключами |
| [`scii_rejected_release_installed`](../rules/scii/correlation/scii_rejected_release_installed.yml) | корреляция | критический | T0862, T1195.002 | устройство установило образ, по которому гейт ранее вынес отказ (тот же SHA-256, окно 30 суток) |
| [`scii_device_management_auth_failures`](../rules/scii/correlation/scii_device_management_auth_failures.yml) | корреляция | средний | T1110 | три и более отказа DENIED в канале управления одного контроллера за 10 минут |

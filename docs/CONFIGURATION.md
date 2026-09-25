# Конфигурация

Файл: `/opt/etc/hotwatcher/config.json`, строгий JSON, права `600`.
Неизвестные поля отклоняются. Значения по умолчанию можно получить командой
`hotwatcher config-example`. Параметр `--config /абсолютный/путь` указывается **перед**
командой: `hotwatcher --config /opt/etc/hotwatcher/config.json status`.

| Поле | По умолчанию | Значение |
|---|---|---|
| `subscription_url_file` | `/opt/etc/hotwatcher/subscription.url` | Приватная копия для updater 0.2.4 и fallback до миграции; основной URL в `07_hotwatcher_api.json` |
| `xray_binary` | `/opt/sbin/xray` | Установленный Xray с API CLI |
| `api_address` | `127.0.0.1:10085` | Только loopback IP, не hostname/WAN/LAN |
| `balancer_tag` | `proxy` | Существующий балансировщик, отдаваемый под управление |
| `xray_config_dir` | `/opt/etc/xray/configs` | Каталог основных JSON |
| `xray_asset_dir` | `/opt/etc/xray/dat` | GeoSite/GeoIP `.dat`, передаётся как `XRAY_LOCATION_ASSET` |
| `generated_file` | `04_outbounds.main.json` | Только `04_outbounds.NAME.json`; не статический `04_outbounds.json` |
| `state_dir` | `/opt/var/lib/hotwatcher` | Приватный каталог `700`, вне confdir |
| `probe_urls` | `https://www.gstatic.com/generate_204` | От 1 до 4 URL; достаточно HTTP 204 хотя бы от одного |
| `url_test_sites` | Google, ChatGPT, YouTube, Discord, Telegram, GitHub | От 1 до 12 публичных HTTPS-доменов; все должны открыться перед выбором ключа. Web UI сохраняет изменения отдельно в `state_dir/url-test-sites.json` и применяет их сразу |
| `webui_enabled` | `true` | Запускать Web UI вместе со службой Hot Watcher |
| `webui_listen` | `127.0.0.1:8787` | Адрес Web UI; только IP loopback или частной локальной сети |
| `probe_timeout_seconds` | `12` | Таймаут одной HTTP-пробы, 1..120 |
| `http_timeout_seconds` | `30` | Загрузка подписки, 1..120 |
| `api_timeout_seconds` | `10` | API deadline; на сам CLI есть небольшой дополнительный запас |
| `interval_seconds` | `1800` | Проверка подписки; минимум 60 |
| `reconcile_seconds` | `60` | Восстановление pin/pool после потери runtime; минимум 10 |
| `key_check_interval_seconds` | `300` | Быстрая HTTPS-проба и URL Test активного ключа; при отказе выбор работающего из сохранённых; 60..3600 |
| `grace_seconds` | `1800` | Минимальное время до `gc`; минимум 60 |
| `automatic_gc` | `false` | Автоудаление retired при очередном успешном неизменном sync |
| `max_nodes` | `64` | Лимит активных уникальных VLESS, 1..256 |
| `max_retired` | `128` | Лимит ещё не удалённых старых узлов, 1..1024 |
| `preferred_name_contains` | пусто | Предпочтение при первичном выборе/исчезновении выбранного endpoint |
| `selection_policy` | `latency` | `latency`: измерять HTTPS-задержку через VLESS и учитывать пороги смены; `sticky`: сохранять текущий узел |
| `key_switch_min_improvement_ms` | `80` | Новый ключ должен быть быстрее минимум на столько миллисекунд, 0..5000 |
| `key_switch_min_improvement_percent` | `20` | И минимум на столько процентов от задержки текущего ключа, 0..100; применяется больший из двух порогов |
| `key_switch_cooldown_seconds` | `1800` | Минимальный интервал между плановыми сменами рабочего ключа, 0..86400; отказ активного ключа обходит этот интервал |
| `static_fallback_tag` | `vless-reality` | Тег статического VLESS outbound в `04_outbounds.json` для `hotwatcher stop` |
| `ca_file` | пусто | Дополнительный PEM bundle для HTTPS; проверка TLS не отключается |
| `allow_tls_nodes` | `false` | Разрешить VLESS+TLS наряду с Reality |
| `allow_loopback_http_for_tests` | `false` | Только для локальных тестов: HTTP на IP loopback |

Параметры `automatic_gc`/`grace_seconds` не измеряют число активных сессий. Включение
автоматической очистки — согласие на best-effort поведение удаления старых handlers.
Для длительных игр оставь `false` и запускай `gc` вне игровой сессии.

Изменения config подхватываются следующей отдельной командой. Для работающего демона
перезапусти **только Hot Watcher**, не Xray:

```sh
/opt/etc/init.d/S99hotwatcher restart
```

Если служба завершает транзакцию и не успела остановиться, init-скрипт не убивает её
принудительно. Проверь `status`, дождись завершения этой локальной операции и повтори
остановку/запуск. При ручном аварийном завершении может потребоваться `recover`.

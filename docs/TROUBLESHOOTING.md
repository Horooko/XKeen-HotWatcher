# Диагностика

Начни без перезапуска основного Xray:

```sh
hotwatcher status
hotwatcher doctor
hotwatcher doctor network
hotwatcher recovery status
hotwatcher keys
tail -n 40 /opt/var/lib/hotwatcher/events.jsonl
cat /opt/var/lib/hotwatcher/last-check.json
```

`status` не выводит URL, UUID, streamSettings или полную конфигурацию узлов.
Во время другого update он может отклонить вызов из-за блокировки: повтори после завершения.

## Типичные случаи

| Сообщение/поле | Действие |
|---|---|
| `handler_service_list_outbounds: false` | Проверить запущенный Xray, адрес localhost API и наличие HandlerService/lso в сборке |
| `routing_service_balancer: false` | Проверить RoutingService и точное имя `proxy`; балancer должен реально существовать |
| `private_subscription_url_file: false` | Проверь `hotwatcher.subscription_url` в `07_hotwatcher_api.json` и права файла `600`; до миграции проверь старый `subscription.url` |
| `compatible_balancer_selector: false` | Селектор должен соответствовать префиксу `main--VL--hw-`, например `main--VL` |
| `subscription download failed` | DNS/интернет/CA/редирект; программа не показывает URL в сообщении |
| `subscription HTTP status 401/403` | Токен/доступ к подписке; старый конфиг не затирается |
| `unrecognized subscription line` | Endpoint отдаёт HTML/JSON/неподдержанный текст вместо URI-списка |
| `unsupported or repeated VLESS parameter` | Сверить docs/SUBSCRIPTIONS.md; не удалять нужный параметр вслепую |
| `TLS node ... allow_tls_nodes is false` | Для нужных VLESS+TLS включить этот параметр; сертификаты всё равно проверяются |
| `staged full ... failed validation` | Проверить `xray_asset_dir`, наличие ext:*.dat, поддержку новых узлов установленным Xray |
| `all active nodes failed HTTPS latency probes` | Ни один узел подписки не дал HTTP 204 через изолированный клиент; старый выбор сохранён. Посмотри `keys`, затем `keys --check` для повторной проверки применённых ключей |
| `XKeen запущен, но API ... недоступен` | XKeen вернулся, но применение отложено из-за API. `keys` покажет загруженные и сохранённые ключи; проверь `xkeen -status`, `hotwatcher doctor` и журналы XKeen/Xray |
| `another Hot Watcher operation is in progress` | Выполни `recovery status`: он проверяет реальную блокировку ядра и показывает PID и операцию. Не удаляй файл `lock`: оставшийся после падения файл сам по себе ничего не блокирует |
| `cannot pin an existing outbound` | Балансировщик пока не имеет действующего target; проверить исходный пул/Observatory |
| `outbound file was changed outside` | Остался cron/другой updater/ручная правка; остановить конфликт, восстановить согласованное состояние |
| `pending_transaction: true` | Не restart; выбрать `recover` или `abort`, см. ROLLBACK.md |
| Прерванный `hard-sync` | `recovery status`, затем `recovery resume` для запуска XKeen и завершения применения либо `recovery abort` для возврата прежнего выбора. Команды не удаляют журнал при ошибке |
| `retired pool limit reached` | Выполнить `gc` вне игры после grace; не удалять state вручную |
| `api_reachable: true`, игра не работает | Доступность API не доказывает UDP или доступность выбранного сервера |

## Обновление остановлено из-за «multiple primary Xray processes»

В версиях до 0.3.3 updater считал любые процессы `/opt/sbin/xray` основными.
При обычной проверке Hot Watcher запускает кратковременные команды `xray api lso`
и `xray api bi`; их совпадение по времени ошибочно блокировало установку.
Остановка обеих служб Hot Watcher не исправляет эту проверку внутри уже
установленного бинарника. В 0.3.3 updater отличает основной сервер от API-команд
и временных проб, а перед установкой и после неё сравнивает все основные процессы.

Если обновление до 0.3.3 блокируется старым updater, используйте один раз
`scripts/repair-updater.sh` из установочного архива нового релиза по инструкции
в [AUTOUPDATE.md](AUTOUPDATE.md). Не удаляйте `lock` и не завершайте процессы
Xray ради обновления Hot Watcher.

Если одновременно `doctor` показывает `handler_service_list_outbounds: false`
и `routing_service_balancer: false`, проверьте процессы и порт API отдельно:

```sh
ps -w | grep '[x]ray'
netstat -ltnp 2>/dev/null | grep ':10085'
```

Строки `xray api lso` и `xray api bi` — клиенты API, а не основной сервер.
Если нет процесса `xray run` и порт `127.0.0.1:10085` не слушает, `hard-sync`
не сможет применить ключи. `xkeen -status` в такой ситуации может ошибочно
посчитать кратковременный API-клиент работающим сервером. Дождитесь завершения
API-команд и восстановите XKeen; если `xkeen -start` снова сообщает «уже
запущен», проверьте, какие именно процессы Xray остались, прежде чем их трогать.

Проверка TLS требует правильных часов роутера. При ошибках сертификатов сначала проверь
`date`, настройки NTP и CA bundle. Не добавляй `insecure`/отключение сертификатов.

## Проба HTTP 204 не проходит, но браузер работает

Проба проходит через конкретный candidate в отдельном Xray. Endpoint может блокироваться
в выбранной стране/на сервере, маршрутизация/маркеры у твоего окружения могут отличаться,
или узел может действительно не работать. Можно настроить другой доверенный HTTPS URL,
который **действительно возвращает 204**, в `probe_urls`.

Не используй обычную главную страницу с 200/302 вместо 204 и не заменяй end-to-end
проверку голым TCP-connect: это не подтвердит работоспособность VLESS.

## Пустой error.log Xray

Пустой error.log не означает доступность серверов и не доказывает причину старого сбоя.
Hot Watcher имеет отдельный журнал. Не делай вывод, что VMess/Trojan автоматически являются
причиной падения: предупреждение о deprecated — не runtime exception.

## Как проверить именно отсутствие рестарта

Запиши основной PID после завершения всех probe-процессов. Выполни update. Сравни PID
и start time основного Xray, проверь доступность своего сервиса и журнал. Установи, не
работают ли параллельно geofile updater, xkeen -restart cron, сторонняя панель или watchdog.

`hotwatcher sync` при одинаковой семантической подписке не создаёт новые handlers.
`applied` означает, что API подтвердил pin и файл/state записаны. Это не монитор всех
пакетов и не доказательство отсутствия утечки IPv4/IPv6.

## Отчёт для анализа

Из каталога распакованного проекта:

```sh
sh scripts/support-report.sh
```

Полученный файл `/tmp/hotwatcher-support-....txt` включает только время, архитектуру,
version/status/doctor и последние очищенные события. Проверь его перед отправкой.
**Не отправляй** `07_hotwatcher_api.json`, `subscription.url`, `state.json`, `pending.json`, pre-migration backup,
исходный crontab или сырой `xray api lso`: они могут содержать учётные данные.

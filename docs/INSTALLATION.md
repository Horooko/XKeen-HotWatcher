# Подробности установки и перехода

Основной маршрут — README. Этот документ описывает отличия и восстановление после
ошибок настройки. Проект рассчитан на Linux/Entware, а не на CLI самой KeeneticOS.

## Совместимость

Целевая пользовательская конфигурация: XKeen 2.0, Linux `aarch64`, Xray 26.7.28,
каталог `/opt/etc/xray/configs`, балансировщик `proxy` с селектором `main--VL`.
**Само совпадение номера версии не является проверкой совместимости API**: конкретная
сборка на роутере не была запущена в среде разработки. `doctor` проверяет наличие
работающих `HandlerService.ListOutbounds` и `RoutingService.GetBalancerInfo` через CLI.
`adopt` дополнительно проверяет `ado`/`bo` и подтверждает результат.

Доступные бинарники: Linux ARM64 (aarch64) и AMD64 (x86_64), CGO выключен. Нет зависимости
от Python/Node/jq/старого watcher. Нет bundled Xray — используется установленный бинарник.
CA bundle требуется для HTTPS. Программа дополнительно ищет Entware CA в
`/opt/etc/ssl/certs/ca-certificates.crt` и `/opt/etc/ssl/cert.pem`. Можно задать `ca_file`.
При отсутствии CA установи системные сертификаты штатным способом Entware, не отключай TLS.

## API уже существует

Не добавляй второй объект `api` в другом JSON. В существующем объекте должны быть:

```json
{
  "api": {
    "tag": "api",
    "listen": "127.0.0.1:10085",
    "services": ["HandlerService", "RoutingService"]
  }
}
```

Сохрани также ранее включённые сервисы, если они нужны другим приложениям.
Указанный порт — пример; `api_address` у Hot Watcher должен совпадать с действующим API.
Для современного упрощённого `listen` не нужны дополнительные API inbound/routing rules.
Если у тебя настроена прежняя схема с отдельным API inbound и маршрутом, не удаляй её
вслепую: она тоже может работать, но доступ должен оставаться только localhost.

После изменения API обычно нужен один плановый restart Xray. **Hot Watcher не может
горячо включить выключенный API через этот же выключенный API.**

## GeoSite/GeoIP и окружение

Штатная раскладка актуального XKeen указывает `/opt/etc/xray/dat`. Это значение
`xray_asset_dir`. Если `.dat` фактически находятся в другом месте, исправь параметр.

Программа убирает наследованные `XRAY_LOCATION_CONFDIR`/`xray.location.confdir` перед
изолированным тестом/пробой, иначе дочерний Xray мог бы случайно прочитать production
конфигурацию. Путь asset задаётся явно. Временные файлы находятся в `state_dir`, не в
боевом confdir. Ссылки вместо файлов в копируемых JSON отклоняются.

## Владение файлами

| Путь | Владелец/назначение |
|---|---|
| `/opt/sbin/hotwatcher` | Новая программа |
| `/opt/etc/hotwatcher/config.json` | Пользовательские настройки |
| `/opt/etc/hotwatcher/subscription.url` | Секретный URL, одна строка |
| `/opt/etc/hotwatcher/enabled` | Разрешение автозапуска службы |
| `/opt/etc/init.d/S99hotwatcher` | Только служба Hot Watcher |
| `/opt/var/lib/hotwatcher/state.json` | Приватные активные/retired узлы и pin |
| `/opt/var/lib/hotwatcher/pending.json` | Незавершённая транзакция, если есть |
| `/opt/var/lib/hotwatcher/events.jsonl` | Очищенные события, ротация 1 MiB + 1 файл |
| `/opt/var/lib/hotwatcher/last-check.json` | Время/результат последнего планового sync |
| `/opt/etc/xray/configs/04_outbounds.main.json` | Управляемый файл, заменяется после успешного hot-apply |
| `/opt/etc/xray/configs/07_hotwatcher_api.json` | API fragment, создаётся отдельным явным шагом |

`05_routing.json`, `03_inbounds.json`, `04_outbounds.json` и netfilter не переписываются.
Настройка cron для геофайлов также не меняется, кроме явного удаления строк старого watcher.

## Служба или cron

Рекомендуется одна служба S99hotwatcher. Она сохраняет pin после отдельного рестарта Xray
и после загрузки роутера; запуск только раз в 30 минут оставлял бы длительное окно без pin.

```sh
/opt/etc/init.d/S99hotwatcher start
/opt/etc/init.d/S99hotwatcher stop
/opt/etc/init.d/S99hotwatcher status
```

Если автозапуск Entware init.d на твоём роутере отключён/иначе устроен, сначала настрой
его штатным способом. Маркер `enabled` без запуска init-скрипта сам по себе службу не
создаёт. Проверка: `S99hotwatcher status`, затем `hotwatcher status`.

Допускается ручной `sync` одновременно с работающей службой: flock либо сериализует
действие, либо отклоняет пересечение сообщением `another ... operation is in progress`.
Не обходи блокировку удалением lock-файла у работающего процесса.

## Старое расширение

Сначала отключи его cron скриптом из проекта. Бинарник старого watcher остаётся и новой
программе не нужен. После проверки работы/отката его можно убрать вручную:

```sh
rm -f /opt/sbin/xkeen-subscription-watcher
```

Это не удаляет подписочный JSON, конфиг Xray или новый Hot Watcher. Не удаляй рабочие
`04_outbounds*.json` просто потому, что удалил старый бинарник.

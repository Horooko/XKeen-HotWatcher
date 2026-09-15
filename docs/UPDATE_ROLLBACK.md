# Восстановление обновления программы

Перед заменой updater сохраняет прежний бинарник в `/opt/var/lib/hotwatcher-updater/versions/<sha256>` и durable журнал `pending-update.json`. Если новая сборка не проходит preflight, validation heartbeat или запуск обычной службы, updater останавливает только Hot Watcher, атомарно возвращает прежний бинарник и блокирует неудачный SHA-256. Он не восстанавливает каталог подписки поверх сторонних изменений и не управляет Xray.

При выключении питания init-служба `S98hotwatcher-updater` вызывает `recover` до запуска `S99hotwatcher`. Не удаляйте `pending-update.json`, `maintenance.json` или предыдущую копию вручную. Сначала проверьте:

```sh
/opt/sbin/hotwatcher-updater recover
/opt/sbin/hotwatcher update status
/opt/etc/init.d/S99hotwatcher status
```

Если запись/диск или предыдущий бинарник повреждены, recovery оставляет журнал для ручного вмешательства. Не запускайте candidate из основного пути только потому, что файл существует. `hotwatcher update rollback` пока не выполняет произвольный локальный откат: v1 гарантирует автоматический откат незавершённой установки и boot recovery, а ручной выбор старой версии требует отдельного подтверждённого metadata. Изменения Xray из других задач таким откатом не отменяются.

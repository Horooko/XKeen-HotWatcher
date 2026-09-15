# Первичные источники и проверенные границы

Дата просмотра: **15 сентября 2026**. Ссылки на ветки `main`/`master` отражают
просмотренную реализацию, но не являются фиксацией commit и не доказывают, что
конкретный пользовательский бинарник 26.7.28 полностью с ней совпадает.

1. **Xray API — официальная документация**  
   https://xtls.github.io/en/config/api.html  
   HandlerService add/remove/list outbounds; RoutingService balancer query/override;
   упрощённый loopback `api.listen`. В проекте это конкретные CLI-команды, не выдуманный
   REST endpoint и не передача URI прямо в ядро.

2. **Xray CLI Add/Remove/List Outbounds — исходники XTLS**  
   https://github.com/XTLS/Xray-core/blob/main/main/commands/all/api/outbounds_add.go  
   https://github.com/XTLS/Xray-core/blob/main/main/commands/all/api/outbounds_remove.go  
   https://github.com/XTLS/Xray-core/blob/main/main/commands/all/api/outbounds_list.go  
   Проверены `ado`, `rmo`, `lso`, server/timeout, JSON outbounds и stdin для добавления.

3. **Xray CLI balancer override/info и общие флаги**  
   https://github.com/XTLS/Xray-core/blob/main/main/commands/all/api/balancer_override.go  
   https://github.com/XTLS/Xray-core/blob/main/main/commands/all/api/balancer_info.go  
   https://github.com/XTLS/Xray-core/blob/main/main/commands/all/api/shared.go  
   `bo -b balancer outboundTag`, `bi balancer`. Проект понимает документированный текстовый
   вывод bi; не требует более нового необязательного `--json` для bi.

4. **Менеджер outbound и выбор балансировщика — исходники XTLS**  
   https://github.com/XTLS/Xray-core/blob/main/app/proxyman/outbound/outbound.go  
   https://github.com/XTLS/Xray-core/blob/main/app/router/balancing.go  
   Префиксный selector и инвалидирование cache при add/remove; приоритет override.
   RemoveHandler просмотренной версии не вызывает Close. Это наблюдение о реализации,
   **не гарантия сохранения UDP/Mux-сессий и не контракт всех будущих релизов**.

5. **Конфигурация routing и Observatory**  
   https://xtls.github.io/en/config/routing.html  
   https://xtls.github.io/en/config/observatory.html  
   Runtime pin не сериализуется обратно в пользовательский routing автоматически.
   В проекте перезапуск/восстановление учтены отдельным reconcile loop.

6. **Окружение Xray — исходники**  
   https://github.com/XTLS/Xray-core/blob/main/common/platform/platform.go  
   Имена confdir/config/asset environment variables и нормализация в uppercase.
   Конфиги дочерней проверки изолируются от production confdir.

7. **Текущий subscription-watcher — первичный репозиторий автора**  
   https://github.com/tkukushkin/xkeen-subscription-watcher  
   Документирует запись `04_outbounds.<tag>.json`, restart при изменении и `--no-restart`.
   Hot Watcher не импортирует его исходники, не запускает его и не требует его бинарник.

8. **XKeen runtime paths — первичный репозиторий**  
   https://github.com/jameszeroX/XKeen/blob/main/docs/runtime-paths.md  
   Подтверждены стандартные confdir, dat, log и init-пути. Они вынесены в параметры там,
   где используются программой; конкретную раскладку нужно проверить на роутере.

## Что является решением этого проекта, а не обещанием upstream

Sticky selection, journal format, критерий end-to-end HTTP 204, политика отказа всей
подписки при неподдержанном VLESS, лимиты, manual GC, hold и restore loop — проектные
решения Hot Watcher. Они покрыты локальными тестами, но не предоставляются автоматически
самим Xray и не означают протестированную бесшовность Destiny 2.

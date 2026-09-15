# Выпуск подписанного релиза

Публичный ключ bootstrap v1 записан в `release-public-key.txt` и закреплён в `internal/updater/update.go`. Локальный seed создан в `.git/update-signing-seed.b64`; он **не отслеживается Git**. Для GitHub Actions maintainer должен сохранить его значение как environment secret `UPDATE_SIGNING_SEED` в защищённом environment `signed-release`. Перед публикацией workflow проверит, что подпись соответствует закреплённому публичному ключу; неверный secret остановит job. Не добавляйте seed в commit, PR или логи.

Создайте защищённый tag `vMAJOR.MINOR.PATCH` на проверенном commit. `.github/workflows/release.yml` выполняет тесты/vet, собирает статические arm64/amd64 assets, создаёт manifest и Ed25519-подпись, проверяет их и публикует draft Release с полным набором файлов. Затем job скачивает assets для проверки SHA256SUMS и публикует Release. В настройках GitHub репозитория включите immutable releases и защиту tag/environment. Не повторно используйте существующий номер версии с другими байтами.

Для готового обновления с 0.2.0 автоматический кандидат должен быть `v0.2.1` или другой более новый patch ветки 0.2. Major/minor и prerelease автоматическая patch-policy откладывает. Raw asset `hotwatcher_vX.Y.Z_linux_arm64` используется для updater; tar.gz предназначен для bootstrap installation. Секреты роутера в release assets не входят.

Код release workflow готов, но создание tag, установка GitHub secret/environment и публикация релиза выполняются владельцем репозитория. До первого подписанного опубликованного релиза `update check` сообщает, что подходящего обновления нет.

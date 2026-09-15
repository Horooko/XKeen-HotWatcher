# Сборка и структура

Код использует Go standard library, без внешних Go-модулей. Минимальная языковая версия
в go.mod — 1.23. Для собственной эксплуатационной сборки используй поддерживаемую
актуальную версию Go. Сведения об исходном снимке записаны в BUILD_INFO.txt;
компилятор опубликованных файлов указан в release workflow.

```sh
go test -race -cover ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o dist/hotwatcher-linux-arm64 ./cmd/hotwatcher
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/hotwatcher-linux-amd64 ./cmd/hotwatcher
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o dist/hotwatcher-updater-linux-arm64 ./cmd/hotwatcher-updater
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/hotwatcher-updater-linux-amd64 ./cmd/hotwatcher-updater
(cd dist && sha256sum hotwatcher-linux-* hotwatcher-updater-linux-* > SHA256SUMS)
```

Или `make test`, `make build`. Исходники могут быть расширены для других Linux-архитектур,
но release workflow собирает бинарники и установочный архив только для двух перечисленных.
Windows/macOS не являются целями запуска: используется Linux flock и Entware runtime.

```text
cmd/hotwatcher/main.go                 CLI и daemon loop
internal/hotwatcher/config.go         Конфигурация и приватный URL
internal/hotwatcher/subscription.go   HTTPS + конвертер VLESS
internal/hotwatcher/runtime.go        CLI adapter Xray + isolated probe
internal/hotwatcher/engine.go         Транзакции, sticky pin, state, GC
internal/hotwatcher/files.go          Atomic replace, flock, private logs
internal/hotwatcher/*_test.go         Unit/fault/process/optional-real tests
scripts/                              Установка API/службы, миграция, отчёт
examples/                             Конфигурации и фиктивная подписка
```

Команды API задаются в runtime.go; запрещено превращать аргументы подписки в shell-код.
Добавляя формат/транспорт, дополни whitelist, нормализацию, отрицательные тесты и
end-to-end smoke с реальным сервером. Не заменяй ошибки неизвестных параметров тихим
игнорированием: это может сломать transport/security.

CI GitHub Actions выполняет tests/vet/build. Отдельный tag-triggered workflow публикует
подписанные Releases при наличии защищённого signing secret; см. [RELEASING.md](RELEASING.md).
SHA256SUMS проверяет целостность файлов, но подлинность обновления программы определяется
Ed25519-подписью manifest.

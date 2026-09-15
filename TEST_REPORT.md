# Отчёт проверки Hot Watcher 0.1.0

Дата: 15 сентября 2026. Среда сборки: Linux AMD64, `go version go1.23.2 linux/amd64`.

## Выполнено

- `go test -race -cover -json ./...`: **54 успешных тестов/подтестов**, **1 пропущенный**, **0 ошибок**.
- `go vet ./...`: успешно.
- `sh -n` для install.sh и всех shell-скриптов: успешно.
- Cross-build Linux ARM64 и Linux AMD64, CGO=0: успешно.
- ELF: ARM aarch64 и x86-64, статически слинкованы, без debug-символов.
- AMD64 бинарник: команды `version` и `config-example` выполнены.
- Контрольные суммы двух бинарников: `sha256sum -c dist/SHA256SUMS` успешно.
- JSON примеров и внутренние Markdown-ссылки: проверены перед упаковкой.

Покрытие операторов по пакетам:

```text
ok  	local/xkeen-hot-watcher/cmd/hotwatcher	1.090s	coverage: 62.0% of statements
ok  	local/xkeen-hot-watcher/internal/hotwatcher	9.495s	coverage: 68.9% of statements
```

В число pass входят именованные подслучаи отрицательных тестов, а не 54 независимых
аппаратных сценариев. Тесты охватывают парсер, файловую/транзакционную логику, CLI,
API adapter с имитацией Xray и отдельный имитируемый probe-процесс.

## Не проверено / пропущено

`TestRealXrayHotAPIPreservesEstablishedTCP` пропущен, потому что в среде нет доступного
реального Xray бинарника. Код теста включён; команда запуска в docs/TESTING.md.
**Это не pass с настоящим Xray.**

Не выполнялись запуск на Keenetic/Entware ARM64, проверка именно Xray 26.7.28,
реальная VLESS+Reality подписка, сценарий Destiny 2/UDP, hardware power-loss,
проверка внешнего IPv4/IPv6 kill-switch и измерение RAM на роутере.

Исходники проверены по официальной документации и текущему коду Xray, но API на
целевой сборке следует подтвердить `hotwatcher doctor`, затем осторожной миграцией
`plan`/`adopt` вне игровой сессии. Официального аудита безопасности не было.

## Успешные сценарии

- `TestCLIInformationalCommands`
- `TestCLIHoldStatusAndErrors`
- `TestCLIPlanLoopbackSubscription`
- `TestAdoptBacksUpAndDoesNotRemoveLegacy`
- `TestFirstSyncRequiresExplicitAdopt`
- `TestRenameOnlyDoesNotMutateRuntimeOrFile`
- `TestKeyRotationPinsNewAndRetainsOld`
- `TestFailedCandidateLeavesEverythingUntouched/parse`
- `TestFailedCandidateLeavesEverythingUntouched/probe`
- `TestFailedCandidateLeavesEverythingUntouched/validation`
- `TestFailedCandidateLeavesEverythingUntouched/download`
- `TestFailedCandidateLeavesEverythingUntouched`
- `TestAPIFailureLeavesJournalRecoverIsIdempotent`
- `TestAbortRestoresBeforeStateAndDoesNotRemoveHandlers`
- `TestExternalWriterConflict`
- `TestHoldPreventsFetchingAndGC`
- `TestReconcileRestoresMissingOwnRuntimeAndPin`
- `TestStateWriteFailureRecoverForward`
- `TestNoAPIWritesDuringPlan`
- `TestBalancerParser`
- `TestFileLockAndSymlinkProtection`
- `TestInvalidSelectorBlocksMigration`
- `TestPreferredAndStickyChoice`
- `TestRuntimeCLIAdapterAndEnvironmentIsolation`
- `TestRuntimeErrorsDoNotExposeRawStderr`
- `TestIsolatedProbeProcessSuccessAndFailure`
- `TestParseMixed`
- `TestBase64Formats`
- `TestStableTagIgnoresNamesOrderAndDuplicates`
- `TestParseRejectsUnsafeOrUnsupported/bad-key`
- `TestParseRejectsUnsafeOrUnsupported/ws-vision`
- `TestParseRejectsUnsafeOrUnsupported/bad-tls-field`
- `TestParseRejectsUnsafeOrUnsupported/no-vless`
- `TestParseRejectsUnsafeOrUnsupported/json`
- `TestParseRejectsUnsafeOrUnsupported/unknown-field`
- `TestParseRejectsUnsafeOrUnsupported/bad-type`
- `TestParseRejectsUnsafeOrUnsupported/encryption`
- `TestParseRejectsUnsafeOrUnsupported/html`
- `TestParseRejectsUnsafeOrUnsupported/bad-uuid`
- `TestParseRejectsUnsafeOrUnsupported/none`
- `TestParseRejectsUnsafeOrUnsupported/bad-sid`
- `TestParseRejectsUnsafeOrUnsupported/empty`
- `TestParseRejectsUnsafeOrUnsupported/insecure`
- `TestParseRejectsUnsafeOrUnsupported/duplicate`
- `TestParseRejectsUnsafeOrUnsupported`
- `TestOneBadVLESSRejectsWholeUpdate`
- `TestEncodedPathDecodedOnlyOnce`
- `TestLoopbackOnlyTestHTTP`
- `TestFetchRedactsURLAndRejectsRedirect`
- `TestFetchOKAndSizeLimit`
- `TestConfigStrictPermissionsAndUnknownFields`
- `TestMetadataNameURLNotPrinted`
- `TestGeneratedFileCannotOverwriteRoutingOrStaticOutbounds`
- `TestTooLongLineRejected`

# Dashboard fixes prepared for 0.3.2

## Fixed

- Use `make("small", "mono", tag)`, not the invalid tag name `small mono`.
- Normalize the existing inventory JSON contract. Embedded `FetchedKey` fields
  are `tag`, `name`, `checked`, and `verified`; inventory flags remain `Selected`,
  `Applied`, etc. The UI also accepts older capitalized fields. Opaque tags are
  used unchanged for selecting and pinning.
- Build key rows before replacing the previous table. Render saved keys even
  while the Xray API is unavailable or its initial check has not finished.
- Start independent, read-only XKeen and Xray health checks when the Web UI server
  starts, without requiring a browser or visiting the System tab. Collect a new
  snapshot every 30 seconds after a check completes and after UI operations.
  Authenticated GET endpoints return cached health; browser polling every five
  seconds does not launch shell commands or freeze during jobs/site editing.
- Distinguish unknown status, Xray process presence, and control API availability.
  A running process does NOT establish that traffic works. Only URL Test checks
  traffic. API failures no longer become an unqualified "Xray: no connection".
- Detect server processes separately from `xray api`, validation and HotWatcher
  probe subprocesses. Failed `/proc` inspection produces unknown, not stopped.
- Accept executable XKeen symlinks; supply the Entware PATH; bound inherited pipe
  waits with `exec.Cmd.WaitDelay`. Existing status/log redaction remains in place.
- Keep API stdout separate from stderr so warnings cannot corrupt JSON parsing.
  Neither raw API output nor stderr is exposed in errors or logs.

## Verification

Local environment: Linux amd64, Go 1.23.2, Node.js 22.

- `node --test tests/webui.test.cjs`: 6 passed.
- Replaying the same suite against the original app: 5 failed, 1 passed.
- `go test -race -cover ./...`: passed.
- `go vet ./...`: passed.
- `make build`: builds HotWatcher and its updater for Linux arm64 and amd64.
- Chromium with the actual HTML/CSS/JavaScript and a fixture matching the Go JSON
  contract: initial key rendering, exact select tag, API failure/process alive,
  and pending initial status passed; no uncaught page errors.

Regression tests cover asynchronous startup without a browser, independent
health workers, cached HTTP endpoints, process filtering, executable symlinks,
Entware PATH, stderr warnings, inventory JSON field names, and saved keys during
API failure. The lightweight Node DOM shim deliberately rejects invalid tags.

These are automated/local tests, not a test on a physical Keenetic router.
The PR does not change production Xray configuration, subscriptions, credentials,
Web UI tokens, updater policy, or the default branch. No release is published by
these changes. Build artifacts are test builds until reviewed/released.

## Router verification after installing the build

Restart only HotWatcher, not Xray. Preserve `/opt/etc/hotwatcher` and
`/opt/var/lib/hotwatcher`; do not re-adopt, delete state, or run hard-sync for this
UI fix. Open the Keys tab directly and confirm that names, tags and verified
states render. Check XKeen status without visiting System. A first snapshot may
show "checking" until its background check finishes. Test select/pin using an
actual key, then use URL Test separately to verify traffic.

If the control API remains unavailable, the panel now distinguishes it from a
running Xray process and displays sanitized HandlerService/RoutingService errors.
Do not enable a public API listener or reset a working Xray configuration merely
to turn an indicator green.

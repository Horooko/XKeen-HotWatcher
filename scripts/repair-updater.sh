#!/bin/sh
# One-time recovery for v0.2.4, whose GitHub Releases decoder rejects "url".
# Run from the extracted, signed-release installation package as root.
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root in Entware shell.' >&2; exit 1; }
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "$(uname -m)" in
 aarch64|arm64) ARCH=arm64 ;;
 x86_64|amd64) ARCH=amd64 ;;
 *) echo 'Unsupported architecture.' >&2; exit 1 ;;
esac
for name in hotwatcher hotwatcher-updater; do
 [ -x "$HERE/dist/$name-linux-$ARCH" ] || { echo "Package binary missing: $name-linux-$ARCH" >&2; exit 1; }
 [ -f "/opt/sbin/$name" ] && [ ! -L "/opt/sbin/$name" ] || { echo "Installed binary unsafe or missing: $name" >&2; exit 1; }
done
[ -f "$HERE/dist/SHA256SUMS" ] || { echo 'Package SHA256SUMS missing.' >&2; exit 1; }
(cd "$HERE/dist" && sha256sum -c SHA256SUMS)
[ ! -e /opt/var/lib/hotwatcher/pending.json ] || { echo 'Resolve subscription transaction first.' >&2; exit 1; }
[ ! -e /opt/var/lib/hotwatcher-updater/pending-update.json ] || { echo 'Resolve software update transaction first.' >&2; exit 1; }
[ -f /opt/var/lib/hotwatcher-updater/state.json ] || { echo 'Updater state missing; inspect before repair.' >&2; exit 1; }
/opt/sbin/hotwatcher update status >/dev/null || { echo 'Updater settings/state invalid; repair them first.' >&2; exit 1; }
EXPECTED=$("$HERE/dist/hotwatcher-linux-$ARCH" version)
[ -n "$EXPECTED" ] || { echo 'Candidate version unavailable.' >&2; exit 1; }
BACKUP=$(mktemp -d /opt/tmp/hotwatcher-repair.XXXXXX)
chmod 700 "$BACKUP"
cp /opt/sbin/hotwatcher "$BACKUP/hotwatcher"
cp /opt/sbin/hotwatcher-updater "$BACKUP/hotwatcher-updater"
cp /opt/var/lib/hotwatcher-updater/state.json "$BACKUP/updater-state.json"
RESTORE=0
TEMP=
install_binary() {
 TEMP=$(mktemp "/opt/sbin/.$2.repair.XXXXXX")
 cp "$1" "$TEMP"
 chmod 700 "$TEMP"
 mv -f "$TEMP" "/opt/sbin/$2"
 TEMP=
}
on_exit() {
 code=$?
 trap - EXIT HUP INT TERM
 if [ -n "$TEMP" ]; then rm -f "$TEMP"; fi
 if [ "$RESTORE" = 1 ]; then
  echo 'Repair failed; restoring previous binaries.' >&2
  set +e
  /opt/etc/init.d/S99hotwatcher stop >/dev/null 2>&1
  /opt/etc/init.d/S98hotwatcher-updater stop >/dev/null 2>&1
  install_binary "$BACKUP/hotwatcher" hotwatcher
  install_binary "$BACKUP/hotwatcher-updater" hotwatcher-updater
  cp "$BACKUP/updater-state.json" /opt/var/lib/hotwatcher-updater/state.json
  chmod 600 /opt/var/lib/hotwatcher-updater/state.json
  [ ! -f /opt/etc/hotwatcher/enabled ] || /opt/etc/init.d/S99hotwatcher start
  [ ! -f /opt/etc/hotwatcher/update-enabled ] || /opt/etc/init.d/S98hotwatcher-updater start
  echo "Previous copies retained in $BACKUP" >&2
 else
  rm -f "$BACKUP/hotwatcher" "$BACKUP/hotwatcher-updater" "$BACKUP/updater-state.json"
  rmdir "$BACKUP"
 fi
 exit "$code"
}
trap on_exit EXIT
trap 'exit 1' HUP INT TERM
RESTORE=1
/opt/etc/init.d/S99hotwatcher stop
/opt/etc/init.d/S98hotwatcher-updater stop
install_binary "$HERE/dist/hotwatcher-linux-$ARCH" hotwatcher
install_binary "$HERE/dist/hotwatcher-updater-linux-$ARCH" hotwatcher-updater
[ "$(/opt/sbin/hotwatcher version)" = "$EXPECTED" ] || { echo 'Installed version differs from package.' >&2; exit 1; }
/opt/sbin/hotwatcher update status >/dev/null
/opt/sbin/hotwatcher update repair-state "$EXPECTED"
if [ -f /opt/etc/hotwatcher/enabled ]; then
 /opt/etc/init.d/S99hotwatcher start
 sleep 2
 /opt/etc/init.d/S99hotwatcher status | grep -q 'Hot Watcher PID:'
fi
if [ -f /opt/etc/hotwatcher/update-enabled ]; then
 /opt/etc/init.d/S98hotwatcher-updater start
fi
RESTORE=0
echo "Updater decoder repaired with Hot Watcher $EXPECTED. Production Xray was not restarted."

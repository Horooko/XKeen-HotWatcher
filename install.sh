#!/bin/sh
# Offline installer. Does not download, restart Xray or edit live routing.
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root in the Entware shell.' >&2; exit 1; }
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "$(uname -m)" in
 aarch64|arm64) ARCH=arm64 ;;
 x86_64|amd64) ARCH=amd64 ;;
 *) echo 'Prebuilt binaries support aarch64 and x86_64 only. See docs/BUILD.md.' >&2; exit 1 ;;
esac
[ -x /opt/sbin/xray ] || { echo '/opt/sbin/xray not found. Edit configuration for another path after manual installation.' >&2; exit 1; }
[ -d /opt/etc/xray/configs ] || { echo 'Existing Xray config directory not found.' >&2; exit 1; }
test -f "$HERE/dist/hotwatcher-linux-$ARCH"
test -f "$HERE/dist/hotwatcher-updater-linux-$ARCH"
(cd "$HERE/dist" && grep " hotwatcher-linux-$ARCH$\| hotwatcher-updater-linux-$ARCH$" SHA256SUMS | sha256sum -c -)
for DIR in /opt/etc/hotwatcher /opt/var/lib/hotwatcher /opt/var/lib/hotwatcher-updater; do
 [ ! -L "$DIR" ] || { echo "Refusing symlink directory: $DIR" >&2; exit 1; }
 mkdir -p "$DIR"
 chmod 700 "$DIR"
done
mkdir -p /opt/sbin /opt/etc/init.d /opt/var/run
[ ! -r /opt/var/run/hotwatcher.pid ] || { echo 'Stop Hot Watcher before bootstrap install; use updater for later program updates.' >&2; exit 1; }
[ ! -r /opt/var/run/hotwatcher-updater.pid ] || { echo 'Stop updater before replacing bootstrap updater or init scripts.' >&2; exit 1; }
[ ! -L /opt/sbin/hotwatcher ] || { echo 'Refusing symlink binary path.' >&2; exit 1; }
TMP=$(mktemp /opt/sbin/.hotwatcher.XXXXXX)
trap 'rm -f "$TMP"' EXIT HUP INT TERM
cp "$HERE/dist/hotwatcher-linux-$ARCH" "$TMP"
chmod 700 "$TMP"
mv -f "$TMP" /opt/sbin/hotwatcher
if [ -f "$HERE/dist/hotwatcher-updater-linux-$ARCH" ]; then
 [ ! -L /opt/sbin/hotwatcher-updater ] || { echo 'Refusing symlink updater.' >&2; exit 1; }
 UPTMP=$(mktemp /opt/sbin/.hotwatcher-updater.XXXXXX)
 cp "$HERE/dist/hotwatcher-updater-linux-$ARCH" "$UPTMP"
 chmod 700 "$UPTMP"
 mv -f "$UPTMP" /opt/sbin/hotwatcher-updater
fi
if [ ! -e /opt/etc/hotwatcher/config.json ]; then
 (umask 077; /opt/sbin/hotwatcher config-example > /opt/etc/hotwatcher/config.json)
fi
if [ ! -e /opt/etc/hotwatcher/subscription.url ]; then
 (umask 077; printf '%s\n' 'https://subscription.example.invalid/REPLACE_ME' > /opt/etc/hotwatcher/subscription.url)
fi
cp "$HERE/scripts/S99hotwatcher" /opt/etc/init.d/S99hotwatcher
chmod 700 /opt/etc/init.d/S99hotwatcher
if [ -f "$HERE/scripts/S98hotwatcher-updater" ]; then
 cp "$HERE/scripts/S98hotwatcher-updater" /opt/etc/init.d/S98hotwatcher-updater
 chmod 700 /opt/etc/init.d/S98hotwatcher-updater
fi
if [ ! -e /opt/etc/hotwatcher/updates.json ] && [ -x /opt/sbin/hotwatcher-updater ]; then
 (umask 077; /opt/sbin/hotwatcher-updater enable --notify >/dev/null)
fi
printf '%s\n' \
 'Installed. Xray, firewall and existing cron entries were not changed.' \
 'Next: read README.md, configure subscription.url and enable localhost API.' \
 'The service is disabled until /opt/etc/hotwatcher/enabled is created.'

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
(cd "$HERE/dist" && sha256sum -c SHA256SUMS)
for DIR in /opt/etc/hotwatcher /opt/var/lib/hotwatcher; do
 [ ! -L "$DIR" ] || { echo "Refusing symlink directory: $DIR" >&2; exit 1; }
 mkdir -p "$DIR"
 chmod 700 "$DIR"
done
mkdir -p /opt/sbin /opt/etc/init.d /opt/var/run
[ ! -L /opt/sbin/hotwatcher ] || { echo 'Refusing symlink binary path.' >&2; exit 1; }
TMP=$(mktemp /opt/sbin/.hotwatcher.XXXXXX)
trap 'rm -f "$TMP"' EXIT HUP INT TERM
cp "$HERE/dist/hotwatcher-linux-$ARCH" "$TMP"
chmod 700 "$TMP"
mv -f "$TMP" /opt/sbin/hotwatcher
if [ ! -e /opt/etc/hotwatcher/config.json ]; then
 (umask 077; /opt/sbin/hotwatcher config-example > /opt/etc/hotwatcher/config.json)
fi
if [ ! -e /opt/etc/hotwatcher/subscription.url ]; then
 (umask 077; printf '%s\n' 'https://subscription.example.invalid/REPLACE_ME' > /opt/etc/hotwatcher/subscription.url)
fi
cp "$HERE/scripts/S99hotwatcher" /opt/etc/init.d/S99hotwatcher
chmod 700 /opt/etc/init.d/S99hotwatcher
printf '%s\n' \
 'Installed. Xray, firewall and existing cron entries were not changed.' \
 'Next: read README.md, configure subscription.url and enable localhost API.' \
 'The service is disabled until /opt/etc/hotwatcher/enabled is created.'

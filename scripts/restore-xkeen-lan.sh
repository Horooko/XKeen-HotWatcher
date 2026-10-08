#!/bin/sh
# Reapply XKeen's own netfilter hook after verified kernel modules are loaded.
set -u
umask 077
PATH=/opt/bin:/opt/sbin:/sbin:/bin:/usr/sbin:/usr/bin
export PATH

hook=/opt/etc/ndm/netfilter.d/proxy.sh
log=/opt/tmp/xkeen-lan-restore-$(date +%Y%m%d-%H%M%S).log

echo 'XKeen LAN rule restore'
if [ ! -f /tmp/.xkeen/ready ] || [ ! -r "$hook" ]; then
    echo 'STOP: XKeen ready marker or netfilter hook is missing.'
    exit 1
fi
if ! pidof xray >/dev/null 2>&1; then
    echo 'STOP: Xray is not running. The hook was not invoked.'
    exit 1
fi
for module in xt_comment xt_dscp xt_multiport xt_socket xt_TPROXY; do
    if ! grep -q "^$module " /proc/modules 2>/dev/null; then
        echo "STOP: kernel module $module is not loaded. The hook was not invoked."
        exit 1
    fi
done

before=$(pidof xray 2>/dev/null)
echo 'Applying the existing XKeen hook; this may briefly interrupt connections.'
if sh "$hook" >"$log" 2>&1; then
    echo 'Hook exit status: OK'
    failed=0
else
    echo 'Hook exit status: FAILED'
    failed=1
fi

check() {
    family=$1
    table=$2
    if "$family" -t "$table" -S xkeen >/dev/null 2>&1 &&
       "$family" -t "$table" -S PREROUTING 2>/dev/null | grep -q ' -j xkeen'; then
        echo "$family $table: chain and PREROUTING jump present"
    else
        echo "$family $table: chain or PREROUTING jump MISSING"
        failed=1
    fi
}

check iptables nat
check iptables mangle
check ip6tables nat
check ip6tables mangle
after=$(pidof xray 2>/dev/null)
if [ "$after" = "$before" ] && [ -n "$after" ]; then
    echo 'Xray PID: unchanged'
else
    echo 'Xray PID: changed or missing; inspect the status report'
    failed=1
fi
echo "Hook log: $log"
if [ "$failed" -eq 0 ]; then
    echo 'LAN interception rules are installed. Test a proxied site without Karing.'
else
    echo 'LAN interception is incomplete. Do not repeat the hook blindly.'
fi
exit "$failed"

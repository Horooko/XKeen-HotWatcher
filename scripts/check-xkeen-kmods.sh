#!/bin/sh
# Read-only check of KeeneticOS Netfilter component and XKeen kernel matches.
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/opt/bin:/opt/sbin
export PATH
LC_ALL=C
export LC_ALL

echo 'XKeen Netfilter module check (read-only)'
echo "Kernel: $(uname -r 2>/dev/null)"
echo
echo '== KeeneticOS installed component names =='
if command -v ndmc >/dev/null 2>&1; then
    ndmc -c 'show version' 2>/dev/null | grep -Ei 'components|opkg-kmod-netfilter|netfilter' || echo 'No matching lines in show version'
    echo
    echo '== KeeneticOS component status =='
    ndmc -c 'show components status' 2>/dev/null | grep -Ei 'netfilter|kernel|module|opkg-kmod' || echo 'No matching lines in show components status'
else
    echo 'ndmc is unavailable'
fi

echo
echo '== Required module state and files =='
for module in xt_comment xt_dscp xt_multiport; do
    echo "[$module]"
    if grep "^$module " /proc/modules 2>/dev/null; then
        :
    else
        echo 'not listed in /proc/modules'
    fi
    found=0
    for directory in /lib/modules /lib/system-modules; do
        if [ -d "$directory" ]; then
            paths=$(find "$directory" -name "$module.ko" -o -name "$module.ko.*" 2>/dev/null)
            if [ -n "$paths" ]; then
                printf '%s\n' "$paths"
                found=1
            fi
        fi
    done
    if [ "$found" -eq 0 ]; then
        echo 'module file not found under /lib/modules or /lib/system-modules'
    fi
done

echo
echo 'Check complete. No services, firewall rules, or network settings were changed.'

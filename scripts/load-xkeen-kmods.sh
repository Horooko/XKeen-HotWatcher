#!/bin/sh
# Load the Netfilter modules required by XKeen Hybrid, without touching rules.
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/opt/bin:/opt/sbin
export PATH
LC_ALL=C
export LC_ALL

kernel=$(uname -r 2>/dev/null)
directory="/lib/modules/$kernel"
echo 'XKeen Hybrid kernel module load check'
echo "Module directory: $directory"

if ! command -v insmod >/dev/null 2>&1; then
    echo 'ERROR: insmod is unavailable'
    exit 1
fi

failed=0
for module in xt_comment xt_dscp xt_multiport xt_socket xt_TPROXY; do
    echo "== $module =="
    if grep -q "^$module " /proc/modules 2>/dev/null; then
        echo 'already loaded'
        continue
    fi
    file="$directory/$module.ko"
    if [ ! -f "$file" ]; then
        echo "ERROR: module file missing: $file"
        failed=1
        continue
    fi
    if insmod "$file" 2>&1; then
        if grep -q "^$module " /proc/modules 2>/dev/null; then
            echo 'loaded successfully'
        else
            echo 'ERROR: insmod returned success but module is not listed'
            failed=1
        fi
    else
        echo 'ERROR: insmod failed'
        failed=1
    fi
done

echo '== Result =='
if [ "$failed" -eq 0 ]; then
    echo 'All required modules are loaded. Firewall rules and services were not changed.'
else
    echo 'At least one module failed. Firewall rules and services were not changed.'
fi
exit "$failed"

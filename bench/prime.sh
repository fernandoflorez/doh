#!/bin/sh
set -eu

dir=$(cd "$(dirname "$0")" && pwd)
for ip in 8.8.8.8 1.1.1.1 9.9.9.9 208.67.222.222; do
    dnsperf -m doh -s "$ip" -p 443 -O "doh-uri=https://$ip/dns-query" \
        -d "$dir/uncached.txt" -n 1 -c 1 -q 20 -Q 200 > /dev/null 2>&1 || true
    echo "primed $ip"
done

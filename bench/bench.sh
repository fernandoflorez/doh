#!/bin/sh
set -eu

if [ $# -ne 3 ]; then
    echo "usage: $0 NAME PORT PID" >&2
    exit 2
fi
name=$1
port=$2
pid=$3
dir=$(cd "$(dirname "$0")" && pwd)

rss_mb() {
    ps -o rss= -p "$pid" | awk '{printf "%.1f", $1 / 1024}'
}

perf() {
    file=$1
    shift
    dnsperf -s 127.0.0.1 -p "$port" -d "$dir/$file" "$@" 2>&1
}

throughput() {
    perf "$1" -l 10 -c 4 -q 200 | awk '
        /Queries per second/ { qps = $4 }
        /Average Latency/ { lat = $4 * 1000 }
        /Queries lost/ { lost = $3 }
        END { printf "%.0f qps, avg %.2f ms, lost %s", qps, lat, lost }'
}

latency() {
    perf "$1" -n 1 -c 1 -q 20 -Q 100 -v |
        awk '/^> NOERROR|^> NXDOMAIN/ { print $NF * 1000 }' | sort -n | awk '
        { v[NR] = $1 }
        END {
            printf "p50 %.1f ms, p95 %.1f ms, p99 %.1f ms (%d answers)",
                v[int(NR * 0.50)], v[int(NR * 0.95)], v[int(NR * 0.99)], NR
        }'
}

echo "== $name"
echo "idle memory:     $(rss_mb) MB"
perf cached.txt -n 1 > /dev/null
echo "cached:          $(throughput cached.txt)"
echo "blocked:         $(throughput blocked.txt)"
echo "uncached:        $(latency uncached.txt)"
echo "memory after:    $(rss_mb) MB"

doh
===

A small, fast DNS-over-HTTPS proxy with Pi-hole style ad blocking, written in Rust.

It listens for regular DNS queries (UDP and TCP) and races every configured DoH provider, answering with the first successful response. By default it uses:

- Google (8.8.8.8)
- Cloudflare (1.1.1.1)
- Quad9 (9.9.9.9)
- OpenDNS (208.67.222.222)

Features:

- In-memory response cache that honors TTLs.
- Blocklists stored in SQLite and loaded into memory at startup; subdomains of blocked domains are blocked too, and so are answers whose CNAME points to a blocked domain.
- Statistics about the fastest provider and the most blocked domains, with automatic cleanup.
- Single-threaded async runtime with a small memory footprint.
- Bounded by design: caps on TCP connections, upstream lookups in flight, cache memory and statistics rows.


## Usage

By default it listens on `127.0.0.1:53`, which is the port the system DNS settings use. Binding port 53 requires root (`sudo`). On Linux you can grant just that capability instead:

```sh
sudo setcap cap_net_bind_service=+ep target/release/doh
```

To listen on another address or port, use `--listen`:

```sh
cargo run -- --listen 127.0.0.1:5300
dig @127.0.0.1 -p 5300 example.com
```

**Exposure:** doh has no client access list and answers anyone who can reach it. Listening on `0.0.0.0` or a LAN address is meant for a trusted local network; never expose it to the Internet (check your firewall and router port forwards), or it becomes an open resolver that can be abused for DNS amplification attacks.

Responses that do not fit in UDP are sent truncated so the client retries over TCP.

Per-query logging (queries, cache hits, blocked domains and the winning provider) is off by default:

```sh
cargo run -- --verbose
```

To pick which DoH servers take part in the race, use `--servers` with built-in names or your own servers as `NAME=URL` (HTTPS only):

```sh
cargo run -- --servers cloudflare,quad9,mine=https://doh.example.com/dns-query
```

Resource limits, all configurable:

| Flag | Default | Limits |
|---|---|---|
| `--max-tcp-connections` | 256 | Simultaneous TCP clients |
| `--max-upstream-queries` | 256 | Cache misses waiting on DoH servers |
| `--max-upstream-per-client` | 32 | Cache misses one client IP can have waiting |
| `--cache-max-mb` | 32 MB | Memory used by cached answers |
| `--max-ttl` | 86,400 s | How long an answer stays cached |
| `--stats-max-rows` | 1,000,000 | Rows kept per statistics table |

Run `cargo run -- --help` to see every option.


## Blocklists

Download a blocklist in hosts or plain domain format, for example https://v.firebog.net/hosts/AdguardDNS.txt, and import it:

```sh
cargo run -- --blocklist AdguardDNS.txt
```

The import exits when it finishes; start the server afterwards. A running server loads the blocklist at startup, so restart it to pick up a new import.

To remove every blocked domain:

```sh
cargo run -- --clear
```

Domains are stored in SQLite, in `doh_blocklist.db` by default (change it with `--db-path`).


## Configuration

Every option can be set in a TOML file, using the flag name as the key (`cache_max_mb` or `cache-max-mb`). Command line flags take precedence over the file. See `contrib/doh.toml` for a commented example.

```toml
listen = "192.168.1.10:53"
servers = ["cloudflare", "quad9"]
cache_max_mb = 64
stats_retention = 30
```

```sh
cargo run -- --config doh.toml
```


## Statistics

The winning provider of each race and every blocked domain are recorded. To print a summary:

```sh
cargo run -- --stats
```

Entries older than 60 days are deleted automatically. To change the retention period:

```sh
cargo run -- --stats-retention 30
```


## Running as a service

`contrib/` contains service files for Linux (systemd) and macOS (launchd). Both expect the binary at `/usr/local/bin/doh`:

```sh
cargo build --release
sudo install -o root -m 755 target/release/doh /usr/local/bin/doh
```

Linux (runs without root thanks to `CAP_NET_BIND_SERVICE`; the database lives in `/var/lib/doh`):

```sh
sudo cp contrib/doh.service /etc/systemd/system/
sudo systemctl enable --now doh
```

macOS (starts as root only to open port 53, then runs as `nobody` thanks to `--user`; the database lives in `/var/db/doh` and errors go to `/var/log/doh.log`, both root-owned locations):

```sh
sudo install -d -o nobody -m 700 /var/db/doh
sudo cp contrib/local.doh.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/local.doh.plist
```

The blocklist is loaded when the service starts. To import a new list into the service database and restart it:

```sh
# Linux (systemd keeps DynamicUser state under /var/lib/private)
sudo doh --db-path /var/lib/private/doh/doh_blocklist.db --blocklist list.txt
sudo systemctl restart doh

# macOS
sudo doh --db-path /var/db/doh/doh_blocklist.db --user nobody --blocklist list.txt
sudo launchctl kickstart -k system/local.doh
```


## Benchmark

Compared with two popular open source ad-blocking DNS proxies, using the same four DoH upstreams, the same blocklist (AdguardDNS from firebog, 190k domains) and default cache settings. Median of three rounds on an Apple M4 Pro (12 cores, 24 GB), macOS 27.0.1, November 2026.

| | doh | Blocky v0.35.0 | AdGuard Home v0.107.80 |
|---|---|---|---|
| Cached queries | **112,583 qps** | 89,032 qps | 89,956 qps |
| Blocked queries | 84,730 qps | 89,925 qps | **90,561 qps** |
| Uncached latency p50 | 9.1 ms | 14.3 ms | **6.5 ms** |
| Uncached latency p95 | **44.4 ms** | 137.6 ms | 86.8 ms |
| Uncached latency p99 | **116.0 ms** | 327.2 ms | 216.8 ms |
| Memory at startup | **34.8 MB** | 52.9 MB | 78.5 MB |
| Memory after the run | **43.6 MB** | 77.6 MB | 113.0 MB |
| Binary size | **4.7 MB** | 32.3 MB | 33.1 MB |

How it was measured:

- Throughput: `dnsperf` for 10 seconds with 4 clients and 200 outstanding queries, against 100 popular domains already in cache and against 1,000 blocked domains.
- Latency: 1,000 popular domains not in the proxy cache, at 100 queries per second. Before measuring, `bench/prime.sh` warms up the upstream servers' caches so the proxy that runs first is not penalized.
- AdGuard Home ran with its rate limit disabled and query log off; Blocky with its default `parallel_best` strategy.
- doh runs on a single thread; Blocky and AdGuard Home use every core.

Blocky and AdGuard Home do much more (web interface, query log, per-client rules), so this compares the DNS path only.

To reproduce, install [dnsperf](https://github.com/DNS-OARC/dnsperf), start the proxy on a local port and run:

```sh
bench/prime.sh
bench/bench.sh doh 5300 <PID>
```

The query lists in `bench/` come from the [Tranco](https://tranco-list.eu) top sites list and the AdguardDNS blocklist.


## Notes

This does not prevent DNS leaks.


## License

[MIT](LICENSE)

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

If doh sits behind a router or another DNS forwarder, every query arrives from that one IP, so raise `--max-upstream-per-client` (for example to the `--max-upstream-queries` value).

Run `cargo run -- --help` to see every option. Without a command doh serves DNS; `import`, `clear` and `stats` manage the database and exit (`cargo run -- stats --help` shows their options).


## Blocklists

Download a blocklist in hosts, plain domain or basic Adblock (`||domain^`) format, for example https://v.firebog.net/hosts/AdguardDNS.txt, and import it (several files can be given at once):

```sh
cargo run -- import AdguardDNS.txt
```

The import exits when it finishes; start the server afterwards. A running server loads the blocklist at startup, so restart it to pick up a new import.

To remove every blocked domain:

```sh
cargo run -- clear
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
cargo run -- stats
```

For scripts and dashboards, `cargo run -- stats --format json` prints the same summary as one JSON object.

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

macOS (starts as root only to open port 53, then runs as `nobody` thanks to `--user`; the database lives in `/var/db/doh`, owned by `nobody` with mode 700, and errors go to the root-owned `/var/log/doh.log`):

```sh
sudo install -d -o nobody -m 700 /var/db/doh
sudo cp contrib/local.doh.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/local.doh.plist
```

The blocklist is loaded when the service starts. Start the service once before the first import, so the database is created by the service user. To import a new list into the service database and restart it:

```sh
# Linux (systemd keeps DynamicUser state under /var/lib/private)
sudo doh --db-path /var/lib/private/doh/doh_blocklist.db import list.txt
sudo systemctl restart doh

# macOS
sudo doh --db-path /var/db/doh/doh_blocklist.db --user nobody import list.txt
sudo launchctl kickstart -k system/local.doh
```


## Benchmark

Compared with two popular open source ad-blocking DNS proxies, using the same four DoH upstreams, the same blocklist (AdguardDNS from firebog, 190k domains) and default cache settings. Median of three rounds on an Apple M4 Pro (12 cores, 24 GB), macOS 27.0.1, November 2026.

| | doh | Blocky v0.35.0 | AdGuard Home v0.107.80 |
|---|---|---|---|
| Cached queries | **105,746 qps** ¹ | 88,815 qps | 90,738 qps |
| Blocked queries | 86,256 qps | 90,213 qps | **90,830 qps** |
| Uncached latency p50 | 9.5 ms | 13.6 ms | **7.8 ms** |
| Uncached latency p95 | **47.3 ms** | 101.6 ms | 89.0 ms |
| Uncached latency p99 | **145.4 ms** | 328.7 ms | 226.5 ms |
| Memory at startup | **30.5 MB** | 53.5 MB | 79.1 MB |
| Memory after the run | **39.6 MB** | 84.5 MB | 112.8 MB |
| Binary size | **4.8 MB** | 32.3 MB | 33.1 MB |

¹ doh dropped about 0.05% of the cached-test queries (336 per round). A few of the 100 test domains return answers that cannot be cached (TTL 0 or no records), so they go upstream on every query; since all `dnsperf` traffic comes from one IP, misses beyond `--max-upstream-per-client` (32) are dropped by design. Blocky and AdGuard Home lost none.

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


## How it was built

This project was developed with the help of two open source agent skills:

- [ponytail](https://github.com/DietrichGebert/ponytail) by Dietrich Gebert: keeps the code lean (YAGNI, standard library first, no unneeded abstractions). Its repository-wide audit was used to remove over-engineering, such as duplicated test servers and redundant cache limits.
- [security-audit-skill](https://github.com/cloudflare/security-audit-skill) by Cloudflare: multi-phase security audits with independently verified findings. Two runs drove the hardening in this repository: HTTPS-only upstreams, reply validation, name filtering, resource limits, CNAME inspection, privilege dropping and ignoring DNS responses. The second, full audit ran its local checks in an isolated Linux sandbox.


## Notes

This does not prevent DNS leaks.

doh does not validate DNSSEC itself; it relies on the upstream DoH resolvers, which do.


## License

[MIT](LICENSE)

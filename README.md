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
- Blocklists stored in SQLite and loaded into memory at startup; subdomains of blocked domains are blocked too.
- Statistics about the fastest provider and the most blocked domains, with automatic cleanup.
- Single-threaded async runtime with a small memory footprint.


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

Responses that do not fit in UDP are sent truncated so the client retries over TCP.

Per-query logging (queries, cache hits, blocked domains and the winning provider) is off by default:

```sh
cargo run -- --verbose
```

To pick which DoH servers take part in the race, use `--servers` with built-in names or your own servers as `NAME=URL`:

```sh
cargo run -- --servers cloudflare,quad9,mine=https://doh.example.com/dns-query
```

Run `cargo run -- --help` to see every option.


## Blocklists

Download a blocklist in hosts or plain domain format, for example https://v.firebog.net/hosts/AdguardDNS.txt, and import it:

```sh
cargo run -- --blocklist AdguardDNS.txt
```

To remove every blocked domain:

```sh
cargo run -- --clear
```

Domains are stored in SQLite, in `doh_blocklist.db` by default (change it with `--db-path`).


## Configuration

Every option can be set in a TOML file, using the flag name as the key (`cache_size` or `cache-size`). Command line flags take precedence over the file. See `contrib/doh.toml` for a commented example.

```toml
listen = "0.0.0.0:53"
servers = ["cloudflare", "quad9"]
cache_size = 20000
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
cargo build --release && sudo cp target/release/doh /usr/local/bin/
```

Linux (runs without root thanks to `CAP_NET_BIND_SERVICE`; the database lives in `/var/lib/doh`):

```sh
sudo cp contrib/doh.service /etc/systemd/system/
sudo systemctl enable --now doh
```

macOS (the database lives in `/usr/local/var/doh` and errors go to `/usr/local/var/log/doh.log`):

```sh
sudo mkdir -p /usr/local/var/doh /usr/local/var/log
sudo cp contrib/local.doh.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/local.doh.plist
```

The blocklist is loaded when the service starts, so restart it after importing a new list into its database with `--db-path`.


## Notes

This does not prevent DNS leaks.


## License

[MIT](LICENSE)

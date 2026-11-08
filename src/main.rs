use clap::{ArgAction, Parser};
use futures::future::select_ok;
use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use reqwest::Client;
use rusqlite::{Connection, Result, params};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufRead};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "A DNS over HTTPS proxy with ad-blocking features.",
    args_override_self = true
)]
struct Args {
    /// TOML file with any of these options (keys use the long flag name).
    /// Command line flags take precedence over the file.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Path to the SQLite database file for the blocklist and statistics.
    #[arg(short, long, default_value = "doh_blocklist.db")]
    db_path: PathBuf,

    /// Import a blocklist from a local file.
    #[arg(short, long, value_name = "FILE")]
    blocklist: Option<PathBuf>,

    /// Clear all domains from the blocklist database.
    #[arg(long)]
    clear: bool,

    /// Address and port to listen on for DNS queries (UDP and TCP).
    #[arg(short, long, default_value = "127.0.0.1:53")]
    listen: SocketAddr,

    /// DoH servers to race, comma separated: google, cloudflare, quad9,
    /// opendns or NAME=URL. Defaults to all the built-in ones.
    #[arg(
        short,
        long,
        value_delimiter = ',',
        value_parser = parse_server,
        action = ArgAction::Set
    )]
    servers: Vec<(&'static str, &'static str)>,

    /// Seconds to wait for a DoH server before giving up on it.
    #[arg(long, value_name = "SECONDS", default_value_t = 5)]
    upstream_timeout: u64,

    /// Maximum number of cached responses.
    #[arg(long, value_name = "ENTRIES", default_value_t = 10_000)]
    cache_size: usize,

    /// TTL in seconds for the answers to blocked domains.
    #[arg(long, value_name = "SECONDS", default_value_t = 60)]
    blocked_ttl: u32,

    /// Seconds an idle TCP client connection is kept open.
    #[arg(long, value_name = "SECONDS", default_value_t = 10)]
    tcp_timeout: u64,

    /// Print the stored statistics and exit.
    #[arg(long)]
    stats: bool,

    /// Days of statistics to keep; older entries are deleted.
    #[arg(long, value_name = "DAYS", default_value_t = 60)]
    stats_retention: u32,

    /// Log every query, cache hit, blocked domain and winning server.
    #[arg(short, long)]
    verbose: bool,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Servers = &'static [(&'static str, &'static str)];
type CacheKey = (String, RecordType);

const DOH_SERVERS: Servers = &[
    ("Google", "https://8.8.8.8/dns-query"),
    ("Cloudflare", "https://1.1.1.1/dns-query"),
    ("Quad9", "https://9.9.9.9/dns-query"),
    ("OpenDNS", "https://208.67.222.222/dns-query"),
];
const STATS_QUEUE: usize = 4096;
const PURGE_EVERY: Duration = Duration::from_secs(3600);

static VERBOSE: AtomicBool = AtomicBool::new(false);

macro_rules! vlog {
    ($($arg:tt)*) => {
        if VERBOSE.load(Ordering::Relaxed) {
            println!($($arg)*);
        }
    };
}

enum Stat {
    Winner(&'static str),
    Blocked(String),
}

struct Resolver {
    client: Client,
    servers: Servers,
    blocklist: HashSet<Box<str>>,
    cache: Mutex<HashMap<CacheKey, (Vec<u8>, Instant)>>,
    stats: SyncSender<Stat>,
    cache_size: usize,
    blocked_ttl: u32,
    tcp_timeout: Duration,
}

fn parse_server(value: &str) -> Result<(&'static str, &'static str), String> {
    if let Some((name, url)) = value.split_once('=') {
        if !url.starts_with("https://") && !url.starts_with("http://") {
            return Err(format!("invalid URL for {name}: {url}"));
        }
        // ponytail: leaked once at startup so every task can share it as 'static
        return Ok((Box::leak(name.into()), Box::leak(url.into())));
    }
    DOH_SERVERS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value))
        .copied()
        .ok_or_else(|| format!("unknown server '{value}', expected a built-in name or NAME=URL"))
}

fn select_servers(servers: &[(&'static str, &'static str)]) -> Servers {
    if servers.is_empty() {
        return DOH_SERVERS;
    }
    Box::leak(servers.to_vec().into_boxed_slice())
}

fn config_args(path: &Path) -> Result<Vec<OsString>, BoxError> {
    let table: toml::Table = std::fs::read_to_string(path)?.parse()?;
    let mut args = Vec::new();
    for (key, value) in table {
        let flag = format!("--{}", key.replace('_', "-"));
        let value = match value {
            toml::Value::Boolean(true) => {
                args.push(flag.into());
                continue;
            }
            toml::Value::Boolean(false) => continue,
            toml::Value::String(s) => s,
            toml::Value::Integer(i) => i.to_string(),
            toml::Value::Array(items) => items
                .into_iter()
                .map(|item| match item {
                    toml::Value::String(s) => Ok(s),
                    other => {
                        Err(format!("{key}: expected strings, got {other}"))
                    }
                })
                .collect::<Result<Vec<_>, _>>()?
                .join(","),
            other => {
                return Err(format!("{key}: unsupported value {other}").into());
            }
        };
        args.push(format!("{flag}={value}").into());
    }
    Ok(args)
}

fn with_config(args: Args, argv: &[OsString]) -> Result<Args, BoxError> {
    let Some(path) = &args.config else {
        return Ok(args);
    };
    let mut merged = argv[..1].to_vec();
    merged.extend(config_args(path)?);
    merged.extend_from_slice(&argv[1..]);
    Ok(Args::try_parse_from(merged)?)
}

async fn doh_req(
    client: &Client,
    (name, url): (&'static str, &'static str),
    domain: &str,
    record_type: RecordType,
) -> Result<(Message, &'static str), BoxError> {
    let mut msg = Message::query();
    msg.add_query(Query::query(Name::from_ascii(domain)?, record_type));
    msg.metadata.recursion_desired = true;

    let response = client
        .post(url)
        .header("Content-Type", "application/dns-message")
        .body(msg.to_vec()?)
        .send()
        .await?
        .bytes()
        .await?;

    Ok((Message::from_bytes(&response)?, name))
}

async fn doh_race(
    client: &Client,
    servers: Servers,
    domain: &str,
    record_type: RecordType,
) -> Result<(Message, &'static str), BoxError> {
    let (winner, _) = select_ok(
        servers
            .iter()
            .map(|&s| Box::pin(doh_req(client, s, domain, record_type))),
    )
    .await?;
    Ok(winner)
}

fn setup_database(db_path: &Path) -> Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS blocklist (
            domain TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS fastest_servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_name TEXT NOT NULL,
            timestamp INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER))
        );
        CREATE TABLE IF NOT EXISTS blocked_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            timestamp INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER))
        );
        CREATE INDEX IF NOT EXISTS idx_fastest_servers_timestamp
            ON fastest_servers (timestamp);
        CREATE INDEX IF NOT EXISTS idx_blocked_requests_timestamp
            ON blocked_requests (timestamp);",
    )?;
    Ok(conn)
}

fn load_blocklist_from_reader<R: BufRead>(
    conn: &mut Connection,
    reader: R,
) -> Result<()> {
    let transaction = conn.transaction()?;
    {
        let mut stmt = transaction
            .prepare("INSERT OR IGNORE INTO blocklist (domain) VALUES (?1)")?;
        let mut count = 0;
        for line in reader
            .lines()
            .map_while(io::Result::ok)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            if let Some(host) = line.split_whitespace().last()
                && stmt.execute(params![host.to_ascii_lowercase()]).is_ok()
            {
                count += 1;
            }
        }
        println!("{} blocklisted domains loaded", count);
    }
    transaction.commit()
}

// ponytail: whole blocklist in a HashSet, a few MB per 100k domains; move to
// an fst or a sorted arena if lists with millions of domains matter
fn load_blocklist(conn: &Connection) -> Result<HashSet<Box<str>>> {
    let mut stmt = conn.prepare("SELECT domain FROM blocklist")?;
    stmt.query_map((), |r| r.get::<_, String>(0).map(String::into_boxed_str))?
        .collect()
}

fn write_stats(
    conn: &mut Connection,
    stats: impl Iterator<Item = Stat>,
) -> Result<()> {
    let transaction = conn.transaction()?;
    for stat in stats {
        match stat {
            Stat::Winner(name) => transaction
                .prepare_cached(
                    "INSERT INTO fastest_servers (server_name) VALUES (?1)",
                )?
                .execute(params![name])?,
            Stat::Blocked(domain) => transaction
                .prepare_cached(
                    "INSERT INTO blocked_requests (domain) VALUES (?1)",
                )?
                .execute(params![domain])?,
        };
    }
    transaction.commit()
}

fn purge_stats(conn: &Connection, retention_days: u32) -> Result<()> {
    let cutoff = format!("-{retention_days} days");
    for table in ["fastest_servers", "blocked_requests"] {
        conn.execute(
            &format!(
                "DELETE FROM {table}
                WHERE timestamp < CAST(strftime('%s', 'now', ?1) AS INTEGER)"
            ),
            params![cutoff],
        )?;
    }
    Ok(())
}

fn spawn_stats_writer(
    mut conn: Connection,
    retention_days: u32,
) -> SyncSender<Stat> {
    let (sender, receiver) = sync_channel(STATS_QUEUE);
    std::thread::spawn(move || {
        let mut last_purge: Option<Instant> = None;
        loop {
            if last_purge.is_none_or(|t| t.elapsed() >= PURGE_EVERY) {
                if let Err(e) = purge_stats(&conn, retention_days) {
                    eprintln!("Error purging stats: {}", e);
                }
                last_purge = Some(Instant::now());
            }
            let first = match receiver.recv_timeout(PURGE_EVERY) {
                Ok(stat) => stat,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return,
            };
            let batch = std::iter::once(first).chain(receiver.try_iter());
            if let Err(e) = write_stats(&mut conn, batch) {
                eprintln!("Error saving stats: {}", e);
            }
        }
    });
    sender
}

fn print_stats(conn: &Connection) -> Result<()> {
    println!("Fastest servers:");
    let mut stmt = conn.prepare(
        "SELECT server_name, COUNT(*), COUNT(*) * 100.0 / SUM(COUNT(*)) OVER ()
        FROM fastest_servers GROUP BY server_name ORDER BY 2 DESC",
    )?;
    let mut rows = stmt.query(())?;
    while let Some(row) = rows.next()? {
        let (name, wins, pct): (String, i64, f64) =
            (row.get(0)?, row.get(1)?, row.get(2)?);
        println!("  {name:<12} {wins:>8} {pct:>6.1}%");
    }

    println!("Most blocked domains:");
    let mut stmt = conn.prepare(
        "SELECT domain, COUNT(*) FROM blocked_requests
        GROUP BY domain ORDER BY 2 DESC LIMIT 10",
    )?;
    let mut rows = stmt.query(())?;
    while let Some(row) = rows.next()? {
        let (domain, blocks): (String, i64) = (row.get(0)?, row.get(1)?);
        println!("  {domain:<40} {blocks:>8}");
    }
    Ok(())
}

fn query_domain(name: &Name) -> Option<String> {
    let labels = name
        .iter()
        .map(|label| {
            label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                .then(|| String::from_utf8_lossy(label).to_ascii_lowercase())
        })
        .collect::<Option<Vec<_>>>()?;
    Some(labels.join("."))
}

fn blocked_response(query: &Query, ttl: u32) -> Message {
    let mut response = Message::response(0, OpCode::Query);
    response.metadata.recursion_desired = true;
    response.metadata.recursion_available = true;
    let rdata = match query.query_type() {
        RecordType::A => Some(RData::A(Ipv4Addr::UNSPECIFIED.into())),
        RecordType::AAAA => Some(RData::AAAA(Ipv6Addr::UNSPECIFIED.into())),
        _ => None,
    };
    if let Some(rdata) = rdata {
        response.add_answer(Record::from_rdata(
            query.name().clone(),
            ttl,
            rdata,
        ));
    }
    response
}

impl Resolver {
    fn new(conn: Connection, args: &Args) -> Result<Self, BoxError> {
        let blocklist = load_blocklist(&conn)?;
        println!("{} blocked domains in memory", blocklist.len());
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(args.upstream_timeout))
                .build()?,
            servers: select_servers(&args.servers),
            blocklist,
            cache: Mutex::default(),
            stats: spawn_stats_writer(conn, args.stats_retention),
            cache_size: args.cache_size,
            blocked_ttl: args.blocked_ttl,
            tcp_timeout: Duration::from_secs(args.tcp_timeout),
        })
    }

    fn is_blocked(&self, domain: &str) -> bool {
        let mut domain = domain;
        loop {
            if self.blocklist.contains(domain) {
                return true;
            }
            match domain.split_once('.') {
                Some((_, parent)) => domain = parent,
                None => return false,
            }
        }
    }

    fn record(&self, stat: Stat) {
        // ponytail: bounded queue, stats are dropped if the writer falls behind
        let _ = self.stats.try_send(stat);
    }

    fn cached(&self, key: &CacheKey) -> Option<Message> {
        let (bytes, expires) = self
            .cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .cloned()?;
        let remaining = expires.checked_duration_since(Instant::now())?;
        let ttl = u32::try_from(remaining.as_secs()).unwrap_or(u32::MAX);
        let mut msg = Message::from_bytes(&bytes).ok()?;
        for record in msg
            .answers
            .iter_mut()
            .chain(&mut msg.authorities)
            .chain(&mut msg.additionals)
        {
            record.ttl = ttl;
        }
        Some(msg)
    }

    fn store(&self, key: CacheKey, msg: &Message) {
        if !matches!(
            msg.response_code,
            ResponseCode::NoError | ResponseCode::NXDomain
        ) {
            return;
        }
        let Some(ttl) = msg
            .answers
            .iter()
            .chain(&msg.authorities)
            .map(|r| r.ttl)
            .min()
        else {
            return;
        };
        let Ok(bytes) = msg.to_vec() else {
            return;
        };
        if ttl == 0 {
            return;
        }

        let now = Instant::now();
        let mut cache =
            self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= self.cache_size {
            cache.retain(|_, (_, expires)| *expires > now);
            // ponytail: no LRU, a cache full of live entries is wiped; add LRU
            // if the hit rate suffers
            if cache.len() >= self.cache_size {
                cache.clear();
            }
        }
        cache.insert(key, (bytes, now + Duration::from_secs(ttl.into())));
    }

    async fn resolve(&self, request: &Message) -> Option<Message> {
        let query = request.queries.first()?;
        let qtype = query.query_type();
        let Some(domain) = query_domain(query.name()) else {
            vlog!("Rejected query with unsupported characters in its name");
            return None;
        };
        vlog!("Query: {} {:?}", domain, qtype);

        let mut response = if self.is_blocked(&domain) {
            vlog!("Blocked: {}", domain);
            self.record(Stat::Blocked(domain));
            blocked_response(query, self.blocked_ttl)
        } else {
            let key = (domain, qtype);
            if let Some(cached) = self.cached(&key) {
                vlog!("Cache hit: {}", key.0);
                cached
            } else {
                match doh_race(&self.client, self.servers, &key.0, qtype).await
                {
                    Ok((msg, name)) => {
                        vlog!("{} won: {}", name, key.0);
                        self.record(Stat::Winner(name));
                        self.store(key, &msg);
                        msg
                    }
                    Err(e) => {
                        vlog!("Error resolving {}: {}", key.0, e);
                        return None;
                    }
                }
            }
        };

        response.metadata.id = request.id;
        response.queries = vec![query.clone()];
        Some(response)
    }
}

fn udp_bytes(
    request: &Message,
    response: &Message,
) -> Result<Vec<u8>, BoxError> {
    let bytes = response.to_vec()?;
    if bytes.len() <= usize::from(request.max_payload()) {
        return Ok(bytes);
    }
    Ok(response.truncate().to_vec()?)
}

async fn serve_udp(socket: UdpSocket, resolver: Arc<Resolver>) {
    let socket = Arc::new(socket);
    let mut buf = [0u8; 4096];
    loop {
        let (size, src) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(e) => {
                vlog!("Error receiving UDP request: {}", e);
                continue;
            }
        };
        let data = buf[..size].to_vec();
        let (socket, resolver) = (Arc::clone(&socket), Arc::clone(&resolver));

        tokio::spawn(async move {
            let Ok(request) = Message::from_bytes(&data) else {
                vlog!("Malformed UDP request from {}", src);
                return;
            };
            let Some(response) = resolver.resolve(&request).await else {
                return;
            };
            match udp_bytes(&request, &response) {
                Ok(bytes) => {
                    if let Err(e) = socket.send_to(&bytes, src).await {
                        vlog!("Error sending UDP response: {}", e);
                    }
                }
                Err(e) => vlog!("Error encoding response: {}", e),
            }
        });
    }
}

async fn handle_tcp(
    mut stream: TcpStream,
    resolver: &Resolver,
) -> Result<(), BoxError> {
    while let Ok(Ok(len)) =
        timeout(resolver.tcp_timeout, stream.read_u16()).await
    {
        let mut data = vec![0; len.into()];
        timeout(resolver.tcp_timeout, stream.read_exact(&mut data)).await??;
        let request = Message::from_bytes(&data)?;
        let Some(response) = resolver.resolve(&request).await else {
            return Ok(());
        };
        let bytes = response.to_vec()?;
        stream.write_u16(u16::try_from(bytes.len())?).await?;
        stream.write_all(&bytes).await?;
    }
    Ok(())
}

async fn serve_tcp(listener: TcpListener, resolver: Arc<Resolver>) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                vlog!("Error accepting TCP connection: {}", e);
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move {
            if let Err(e) = handle_tcp(stream, &resolver).await {
                vlog!("Error handling TCP connection: {}", e);
            }
        });
    }
}

async fn serve(
    socket: UdpSocket,
    listener: TcpListener,
    resolver: Arc<Resolver>,
) {
    tokio::join!(
        serve_udp(socket, Arc::clone(&resolver)),
        serve_tcp(listener, resolver)
    );
}

fn prepare(args: &Args) -> Result<Option<Connection>, BoxError> {
    let mut conn = setup_database(&args.db_path)?;

    if args.clear {
        conn.execute("DELETE FROM blocklist", ())?;
        println!("Blocklist cleared.");
        return Ok(None);
    }

    if args.stats {
        print_stats(&conn)?;
        return Ok(None);
    }

    if let Some(path) = &args.blocklist {
        println!("Loading blocklist from: {:?}", path);
        load_blocklist_from_reader(
            &mut conn,
            io::BufReader::new(File::open(path)?),
        )?;
    }
    Ok(Some(conn))
}

async fn run(argv: Vec<OsString>) -> Result<(), BoxError> {
    let args = with_config(Args::parse_from(&argv), &argv)?;
    VERBOSE.store(args.verbose, Ordering::Relaxed);
    let Some(conn) = prepare(&args)? else {
        return Ok(());
    };
    let resolver = Resolver::new(conn, &args)?;
    let socket = UdpSocket::bind(args.listen).await?;
    let listener = TcpListener::bind(args.listen).await?;
    println!("DNS server listening on {}", args.listen);
    serve(socket, listener, Arc::new(resolver)).await;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    if let Err(e) = run(std::env::args_os().collect()).await {
        if let Some(e) = e.downcast_ref::<clap::Error>() {
            e.exit();
        }
        eprintln!("Error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::MessageType;
    use std::io::Cursor;
    use std::sync::atomic::AtomicUsize;

    fn leak_servers(v: Vec<(&'static str, &'static str)>) -> Servers {
        Box::leak(v.into_boxed_slice())
    }

    fn temp_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "doh-test-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn memory_db() -> Connection {
        setup_database(Path::new(":memory:")).unwrap()
    }

    fn args(db_path: PathBuf) -> Args {
        Args {
            db_path,
            blocklist: None,
            clear: false,
            listen: "127.0.0.1:0".parse().unwrap(),
            config: None,
            servers: vec![],
            upstream_timeout: 5,
            cache_size: 10_000,
            blocked_ttl: 60,
            tcp_timeout: 10,
            stats: false,
            stats_retention: 60,
            verbose: false,
        }
    }

    fn resolver(conn: Connection, servers: Servers) -> Resolver {
        let mut args = args(PathBuf::from(":memory:"));
        args.servers = servers.to_vec();
        Resolver::new(conn, &args).unwrap()
    }

    fn count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), (), |r| {
            r.get(0)
        })
        .unwrap()
    }

    /// Espera a que el hilo de estadísticas escriba `expected` filas.
    fn wait_count(path: &Path, table: &str, expected: i64) {
        for _ in 0..100 {
            if count(&Connection::open(path).unwrap(), table) == expected {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("{table} never reached {expected} rows");
    }

    /// URL de un puerto TCP cerrado: cualquier request falla con conexión rechazada.
    fn dead_url() -> &'static str {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url =
            format!("http://{}/dns-query", listener.local_addr().unwrap());
        Box::leak(url.into_boxed_str())
    }

    /// Servidor DoH mínimo: responde cada query con `records` registros A
    /// fijos (TTL 60) y cuenta cuántas peticiones recibió.
    async fn mock_doh(
        answer: Ipv4Addr,
        records: usize,
    ) -> (&'static str, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url =
            format!("http://{}/dns-query", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    let (start, len) = loop {
                        let n = stream.read(&mut chunk).await.unwrap();
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(i) =
                            buf.windows(4).position(|w| w == b"\r\n\r\n")
                        {
                            let head = String::from_utf8_lossy(&buf[..i])
                                .to_ascii_lowercase();
                            let len: usize = head
                                .lines()
                                .find_map(|l| {
                                    l.strip_prefix("content-length:")
                                })
                                .unwrap()
                                .trim()
                                .parse()
                                .unwrap();
                            break (i + 4, len);
                        }
                    };
                    while buf.len() < start + len {
                        let n = stream.read(&mut chunk).await.unwrap();
                        buf.extend_from_slice(&chunk[..n]);
                    }

                    let mut res =
                        Message::from_bytes(&buf[start..start + len]).unwrap();
                    res.metadata.message_type = MessageType::Response;
                    let name = res.queries[0].name().clone();
                    for _ in 0..records {
                        res.add_answer(Record::from_rdata(
                            name.clone(),
                            60,
                            RData::A(answer.into()),
                        ));
                    }
                    let body = res.to_vec().unwrap();
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(head.as_bytes()).await.unwrap();
                    stream.write_all(&body).await.unwrap();
                });
            }
        });
        (Box::leak(url.into_boxed_str()), hits)
    }

    async fn start(conn: Connection, servers: Servers) -> SocketAddr {
        VERBOSE.store(true, Ordering::Relaxed);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let resolver = Arc::new(resolver(conn, servers));
        tokio::spawn(serve(socket, listener, resolver));
        addr
    }

    fn query_bytes(domain: &str, qtype: RecordType) -> Vec<u8> {
        let mut msg = Message::query();
        msg.metadata.id = 4242;
        msg.add_query(Query::query(Name::from_ascii(domain).unwrap(), qtype));
        msg.to_vec().unwrap()
    }

    async fn send_raw(addr: SocketAddr, data: &[u8]) -> Option<Message> {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(data, addr).await.unwrap();
        let mut buf = [0u8; 4096];
        let recv = client.recv_from(&mut buf);
        let (n, _) = timeout(Duration::from_millis(1500), recv)
            .await
            .ok()?
            .unwrap();
        Some(Message::from_bytes(&buf[..n]).unwrap())
    }

    async fn ask(
        addr: SocketAddr,
        domain: &str,
        qtype: RecordType,
    ) -> Option<Message> {
        send_raw(addr, &query_bytes(domain, qtype)).await
    }

    async fn ask_tcp(
        addr: SocketAddr,
        domain: &str,
        qtype: RecordType,
    ) -> Message {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let query = query_bytes(domain, qtype);
        stream.write_u16(query.len() as u16).await.unwrap();
        stream.write_all(&query).await.unwrap();
        let len = stream.read_u16().await.unwrap();
        let mut buf = vec![0; len.into()];
        stream.read_exact(&mut buf).await.unwrap();
        Message::from_bytes(&buf).unwrap()
    }

    fn blocked_db(path: &Path) -> Connection {
        let mut conn = setup_database(path).unwrap();
        load_blocklist_from_reader(&mut conn, Cursor::new("ads.example.com"))
            .unwrap();
        conn
    }

    fn a_response(ttl: u32) -> Message {
        let mut msg = Message::response(1, OpCode::Query);
        msg.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            ttl,
            RData::A(Ipv4Addr::new(1, 2, 3, 4).into()),
        ));
        msg
    }

    fn key(domain: &str) -> CacheKey {
        (domain.to_string(), RecordType::A)
    }

    #[test]
    fn load_blocklist_skips_comments_blanks_and_duplicates() {
        let mut conn = memory_db();
        let input = "# comment\n\n0.0.0.0 ads.example.com\ntracker.example.org\nADS.Example.com\n";
        load_blocklist_from_reader(&mut conn, Cursor::new(input)).unwrap();

        let mut domains: Vec<_> =
            load_blocklist(&conn).unwrap().into_iter().collect();
        domains.sort();
        assert_eq!(
            domains,
            ["ads.example.com".into(), "tracker.example.org".into()]
        );
    }

    #[test]
    fn prepare_loads_blocklist_then_clear_empties_it() {
        let db_path = temp_path("prepare.db");
        let list_path = temp_path("list.txt");
        std::fs::write(&list_path, "a.example.com\nb.example.com\n").unwrap();

        let mut args = args(db_path.clone());
        args.blocklist = Some(list_path);
        let conn = prepare(&args).unwrap().unwrap();
        assert_eq!(count(&conn, "blocklist"), 2);
        drop(conn);

        args.blocklist = None;
        args.clear = true;
        assert!(prepare(&args).unwrap().is_none());
        let conn = Connection::open(&db_path).unwrap();
        assert_eq!(count(&conn, "blocklist"), 0);
    }

    #[test]
    fn prepare_fails_on_missing_blocklist_file() {
        let mut args = args(PathBuf::from(":memory:"));
        args.blocklist = Some(temp_path("missing.txt"));
        assert!(prepare(&args).is_err());
    }

    #[test]
    fn blocks_listed_domains_and_their_subdomains_only() {
        let resolver =
            resolver(blocked_db(Path::new(":memory:")), DOH_SERVERS);
        assert!(resolver.is_blocked("ads.example.com"));
        assert!(resolver.is_blocked("x.y.ads.example.com"));
        assert!(!resolver.is_blocked("example.com"));
        assert!(!resolver.is_blocked("badads.example.com"));
    }

    #[test]
    fn stats_writer_persists_in_background() {
        let path = temp_path("stats.db");
        let sender = spawn_stats_writer(setup_database(&path).unwrap(), 60);
        sender.send(Stat::Winner("Live")).unwrap();
        sender
            .send(Stat::Blocked("ads.example.com".into()))
            .unwrap();
        wait_count(&path, "fastest_servers", 1);
        wait_count(&path, "blocked_requests", 1);
    }

    #[test]
    fn stats_write_fails_without_tables() {
        let mut conn = Connection::open_in_memory().unwrap();
        let res = write_stats(&mut conn, std::iter::once(Stat::Winner("A")));
        assert!(res.is_err());
        // El hilo registra el error y sigue vivo.
        let sender = spawn_stats_writer(conn, 60);
        sender.send(Stat::Winner("A")).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        sender.send(Stat::Winner("B")).unwrap();
    }

    #[test]
    fn cache_returns_entry_with_decreasing_ttl() {
        let resolver = resolver(memory_db(), DOH_SERVERS);
        resolver.store(key("example.com"), &a_response(300));
        let cached = resolver.cached(&key("example.com")).unwrap();
        let ttl = cached.answers[0].ttl;
        assert!(ttl > 0 && ttl <= 300, "ttl = {ttl}");
        assert!(resolver.cached(&key("other.com")).is_none());
    }

    #[test]
    fn cache_skips_errors_zero_ttl_and_empty_answers() {
        let resolver = resolver(memory_db(), DOH_SERVERS);

        let mut servfail = a_response(300);
        servfail.metadata.response_code = ResponseCode::ServFail;
        resolver.store(key("servfail.com"), &servfail);
        resolver.store(key("zero.com"), &a_response(0));
        resolver.store(key("empty.com"), &Message::response(1, OpCode::Query));

        assert!(resolver.cache.lock().unwrap().is_empty());
    }

    #[test]
    fn cache_drops_expired_entries() {
        let resolver = resolver(memory_db(), DOH_SERVERS);
        let bytes = a_response(300).to_vec().unwrap();
        resolver
            .cache
            .lock()
            .unwrap()
            .insert(key("old.com"), (bytes, Instant::now()));
        std::thread::sleep(Duration::from_millis(5));
        assert!(resolver.cached(&key("old.com")).is_none());
    }

    #[test]
    fn cache_evicts_when_full() {
        let mut resolver = resolver(memory_db(), DOH_SERVERS);
        resolver.cache_size = 100;
        let msg = a_response(300);
        for i in 0..100 {
            resolver.store(key(&format!("d{i}.com")), &msg);
        }
        assert_eq!(resolver.cache.lock().unwrap().len(), 100);
        resolver.store(key("one-more.com"), &msg);
        assert_eq!(resolver.cache.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn race_returns_first_success() {
        let (live, _) = mock_doh(Ipv4Addr::new(1, 2, 3, 4), 1).await;
        let servers = leak_servers(vec![("Dead", dead_url()), ("Live", live)]);

        let (res, name) =
            doh_race(&Client::new(), servers, "example.com", RecordType::A)
                .await
                .unwrap();

        assert_eq!(name, "Live");
        assert_eq!(
            res.answers[0].data,
            RData::A(Ipv4Addr::new(1, 2, 3, 4).into())
        );
    }

    #[tokio::test]
    async fn race_fails_when_all_servers_fail() {
        let servers = leak_servers(vec![("A", dead_url()), ("B", dead_url())]);
        let res =
            doh_race(&Client::new(), servers, "example.com", RecordType::A)
                .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn serve_blocks_listed_domains_by_record_type() {
        let db_path = temp_path("serve-blocked.db");
        let addr = start(
            blocked_db(&db_path),
            leak_servers(vec![("Dead", dead_url())]),
        )
        .await;

        let a = ask(addr, "ads.example.com.", RecordType::A).await.unwrap();
        assert_eq!(a.id, 4242);
        assert_eq!(a.message_type, MessageType::Response);
        assert_eq!(a.answers[0].data, RData::A(Ipv4Addr::UNSPECIFIED.into()));
        assert_eq!(a.answers[0].ttl, 60);

        let aaaa = ask(addr, "Sub.ADS.example.com.", RecordType::AAAA)
            .await
            .unwrap();
        assert_eq!(
            aaaa.answers[0].data,
            RData::AAAA(Ipv6Addr::UNSPECIFIED.into())
        );

        // Tipos distintos de A/AAAA reciben respuesta vacía en vez de timeout.
        let mx = ask(addr, "ads.example.com.", RecordType::MX).await.unwrap();
        assert_eq!(mx.response_code, ResponseCode::NoError);
        assert!(mx.answers.is_empty());

        wait_count(&db_path, "blocked_requests", 3);
    }

    #[tokio::test]
    async fn serve_forwards_to_doh_and_caches_the_answer() {
        let (live, hits) = mock_doh(Ipv4Addr::new(9, 9, 9, 9), 1).await;
        let db_path = temp_path("serve-forward.db");
        let addr =
            start(blocked_db(&db_path), leak_servers(vec![("Live", live)]))
                .await;

        let first =
            ask(addr, "good.example.com.", RecordType::A).await.unwrap();
        let second =
            ask(addr, "GOOD.example.com.", RecordType::A).await.unwrap();

        assert_eq!(hits.load(Ordering::SeqCst), 1);
        for res in [&first, &second] {
            assert_eq!(res.id, 4242);
            assert_eq!(
                res.answers[0].data,
                RData::A(Ipv4Addr::new(9, 9, 9, 9).into())
            );
        }
        // La pregunta se devuelve tal como la escribió el cliente.
        assert_eq!(second.queries[0].name().to_utf8(), "GOOD.example.com.");
        wait_count(&db_path, "fastest_servers", 1);
    }

    #[tokio::test]
    async fn serve_truncates_large_udp_answers_and_serves_them_over_tcp() {
        let (live, _) = mock_doh(Ipv4Addr::new(7, 7, 7, 7), 50).await;
        let addr =
            start(memory_db(), leak_servers(vec![("Live", live)])).await;

        let udp = ask(addr, "big.example.com.", RecordType::A).await.unwrap();
        assert!(udp.truncation);
        assert!(udp.answers.is_empty());

        let tcp = ask_tcp(addr, "big.example.com.", RecordType::A).await;
        assert!(!tcp.truncation);
        assert_eq!(tcp.answers.len(), 50);
    }

    #[tokio::test]
    async fn serve_tcp_closes_on_malformed_or_unresolvable_requests() {
        let addr =
            start(memory_db(), leak_servers(vec![("Dead", dead_url())])).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_u16(1).await.unwrap();
        stream.write_all(&[0xff]).await.unwrap();
        assert!(stream.read_u16().await.is_err());

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let query = query_bytes("good.example.com.", RecordType::A);
        stream.write_u16(query.len() as u16).await.unwrap();
        stream.write_all(&query).await.unwrap();
        assert!(stream.read_u16().await.is_err());
    }

    #[tokio::test]
    async fn serve_ignores_unresolvable_empty_and_malformed_requests() {
        let addr =
            start(memory_db(), leak_servers(vec![("Dead", dead_url())])).await;

        assert!(
            ask(addr, "good.example.com.", RecordType::A)
                .await
                .is_none()
        );
        assert!(
            send_raw(addr, &Message::query().to_vec().unwrap())
                .await
                .is_none()
        );
        assert!(send_raw(addr, &[0xff]).await.is_none());
    }

    #[test]
    fn purge_stats_deletes_only_entries_older_than_retention() {
        let conn = memory_db();
        conn.execute_batch(
            "INSERT INTO fastest_servers (server_name, timestamp)
                VALUES ('Old', CAST(strftime('%s', 'now', '-61 days') AS INTEGER));
            INSERT INTO fastest_servers (server_name) VALUES ('New');
            INSERT INTO blocked_requests (domain, timestamp)
                VALUES ('old.com', CAST(strftime('%s', 'now', '-61 days') AS INTEGER));
            INSERT INTO blocked_requests (domain) VALUES ('new.com');",
        )
        .unwrap();

        purge_stats(&conn, 60).unwrap();

        assert_eq!(count(&conn, "fastest_servers"), 1);
        assert_eq!(count(&conn, "blocked_requests"), 1);
        let name: String = conn
            .query_row("SELECT server_name FROM fastest_servers", (), |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(name, "New");
    }

    #[test]
    fn stats_writer_purges_on_startup() {
        let path = temp_path("purge.db");
        let conn = setup_database(&path).unwrap();
        conn.execute(
            "INSERT INTO blocked_requests (domain, timestamp) VALUES ('old.com', 0)",
            (),
        )
        .unwrap();
        let _sender = spawn_stats_writer(conn, 60);
        wait_count(&path, "blocked_requests", 0);
    }

    #[test]
    fn prepare_with_stats_prints_report_and_exits() {
        let db_path = temp_path("report.db");
        let conn = setup_database(&db_path).unwrap();
        conn.execute_batch(
            "INSERT INTO fastest_servers (server_name)
                VALUES ('Cloudflare'), ('Cloudflare'), ('Google');
            INSERT INTO blocked_requests (domain) VALUES ('ads.example.com');",
        )
        .unwrap();
        drop(conn);

        let mut args = args(db_path);
        args.stats = true;
        assert!(prepare(&args).unwrap().is_none());
    }

    fn argv(args: &[&str]) -> Vec<OsString> {
        std::iter::once("doh")
            .chain(args.iter().copied())
            .map(OsString::from)
            .collect()
    }

    fn write_config(name: &str, content: &str) -> PathBuf {
        let path = temp_path(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn servers_accept_builtin_names_and_custom_urls() {
        let args = Args::parse_from(argv(&[
            "--servers",
            "cloudflare,OPENDNS,mine=https://doh.example.com/dns-query",
        ]));
        assert_eq!(
            select_servers(&args.servers),
            [
                ("Cloudflare", "https://1.1.1.1/dns-query"),
                ("OpenDNS", "https://208.67.222.222/dns-query"),
                ("mine", "https://doh.example.com/dns-query"),
            ]
        );
        assert_eq!(select_servers(&[]), DOH_SERVERS);
        assert!(Args::try_parse_from(argv(&["-s", "nope"])).is_err());
        assert!(Args::try_parse_from(argv(&["-s", "x=ftp://a"])).is_err());
    }

    #[test]
    fn config_file_sets_options_and_cli_overrides_it() {
        let path = write_config(
            "config.toml",
            r#"
            listen = "0.0.0.0:5300"
            cache_size = 500
            verbose = true
            clear = false
            servers = ["quad9", "mine=https://doh.example.com/dns-query"]
            "#,
        );
        let cli = argv(&[
            "--config",
            path.to_str().unwrap(),
            "--listen",
            "127.0.0.1:5301",
            "--servers",
            "google",
        ]);
        let args = with_config(Args::parse_from(&cli), &cli).unwrap();

        assert_eq!(args.listen, "127.0.0.1:5301".parse().unwrap());
        assert_eq!(args.cache_size, 500);
        assert!(args.verbose);
        assert!(!args.clear);
        assert_eq!(args.servers, [("Google", "https://8.8.8.8/dns-query")]);
        assert_eq!(args.blocked_ttl, 60);
    }

    #[test]
    fn config_without_cli_overrides_keeps_file_values() {
        let path = write_config(
            "config-servers.toml",
            "servers = [\"quad9\", \"cloudflare\"]\nblocked-ttl = 5\n",
        );
        let cli = argv(&["-c", path.to_str().unwrap()]);
        let args = with_config(Args::parse_from(&cli), &cli).unwrap();
        assert_eq!(args.servers.len(), 2);
        assert_eq!(args.blocked_ttl, 5);
        assert!(with_config(args, &argv(&[])).is_ok());
    }

    #[test]
    fn config_rejects_unknown_keys_bad_values_and_missing_files() {
        for (name, content) in [
            ("unknown.toml", "nope = 1"),
            ("table.toml", "[section]\nkey = 1"),
            ("array.toml", "servers = [1, 2]"),
            ("type.toml", "cache_size = \"many\""),
            ("syntax.toml", "listen ="),
        ] {
            let path = write_config(name, content);
            let cli = argv(&["-c", path.to_str().unwrap()]);
            assert!(
                with_config(Args::parse_from(&cli), &cli).is_err(),
                "{name}"
            );
        }
        let cli = argv(&["-c", temp_path("missing.toml").to_str().unwrap()]);
        assert!(with_config(Args::parse_from(&cli), &cli).is_err());
    }

    #[tokio::test]
    async fn run_fails_cleanly_on_bad_config() {
        let cli = argv(&["-c", temp_path("absent.toml").to_str().unwrap()]);
        assert!(run(cli).await.is_err());
    }

    #[tokio::test]
    async fn run_prints_stats_and_exits() {
        let db = temp_path("run-stats.db");
        assert!(
            run(argv(&["-d", db.to_str().unwrap(), "--stats"]))
                .await
                .is_ok()
        );
    }

    fn raw_query(labels: &[&[u8]], qtype: RecordType) -> Vec<u8> {
        let mut msg = Message::query();
        msg.metadata.id = 4242;
        let name = Name::from_labels(labels.iter().copied()).unwrap();
        msg.add_query(Query::query(name, qtype));
        msg.to_vec().unwrap()
    }

    #[tokio::test]
    async fn dot_inside_label_does_not_bypass_blocklist() {
        let (live, hits) = mock_doh(Ipv4Addr::new(1, 2, 3, 4), 1).await;
        let addr = start(
            blocked_db(&temp_path("dot-label.db")),
            leak_servers(vec![("Live", live)]),
        )
        .await;

        // Un byte '.' dentro del último label se escapaba como "\." y el
        // trim del punto final dejaba "ads.example.com\", que no matcheaba
        // la blocklist pero se reenviaba como ads.example.com.
        let variants: [&[&[u8]]; 2] = [
            &[b"ads", b"example", b"com."],
            &[b"ads", b"example", b"com", b"."],
        ];
        for labels in variants {
            let res = send_raw(addr, &raw_query(labels, RecordType::A)).await;
            let leaked = res.is_some_and(|r| {
                r.answers.iter().any(|a| {
                    a.data == RData::A(Ipv4Addr::new(1, 2, 3, 4).into())
                })
            });
            assert!(!leaked, "blocked domain resolved for {labels:?}");
        }
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn control_characters_never_reach_stats() {
        let db_path = temp_path("control-chars.db");
        let addr = start(
            blocked_db(&db_path),
            leak_servers(vec![("Dead", dead_url())]),
        )
        .await;

        // Label punycode con ESC en sus code points básicos, bajo un dominio
        // bloqueado; luego una consulta normal que marca el final.
        let evil: &[&[u8]] =
            &[b"xn--\x1b[2K\x1b[1A\x1b[2K-olb", b"ads", b"example", b"com"];
        send_raw(addr, &raw_query(evil, RecordType::A)).await;
        ask(addr, "ads.example.com.", RecordType::A).await.unwrap();

        let conn = Connection::open(&db_path).unwrap();
        let domains: Vec<String> = (0..100)
            .find_map(|_| {
                let mut stmt = conn
                    .prepare("SELECT domain FROM blocked_requests")
                    .unwrap();
                let rows: Vec<String> = stmt
                    .query_map((), |r| r.get(0))
                    .unwrap()
                    .map(|d| d.unwrap())
                    .collect();
                if rows.iter().any(|d| d == "ads.example.com") {
                    return Some(rows);
                }
                std::thread::sleep(Duration::from_millis(20));
                None
            })
            .expect("stats never written");
        for domain in &domains {
            assert!(
                !domain.chars().any(char::is_control),
                "control characters stored: {domain:?}"
            );
        }
    }

    #[test]
    fn query_domain_lowercases_and_rejects_unsafe_labels() {
        let name = |labels: &[&[u8]]| {
            Name::from_labels(labels.iter().copied()).unwrap()
        };
        assert_eq!(
            query_domain(&name(&[b"WWW", b"Example", b"COM"])).as_deref(),
            Some("www.example.com")
        );
        assert_eq!(
            query_domain(&name(&[b"_dmarc", b"my-site", b"org"])).as_deref(),
            Some("_dmarc.my-site.org")
        );
        // Los IDN se mantienen en punycode en vez de decodificarse.
        assert_eq!(
            query_domain(&name(&[b"xn--bcher-kva", b"example"])).as_deref(),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(query_domain(&Name::root()).as_deref(), Some(""));
        for bad in [
            &[b"com." as &[u8]][..],
            &[b"xn--\x1b[2K-olb", b"ads"],
            &[b"a b", b"com"],
            &[b"caf\xc3\xa9", b"com"],
        ] {
            assert_eq!(query_domain(&name(bad)), None, "{bad:?}");
        }
    }
}

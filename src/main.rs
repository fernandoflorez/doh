use clap::Parser;
use futures::future::select_ok;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use reqwest::Client;
use rusqlite::{Connection, Result, params};
use std::fs::File;
use std::io::{self, BufRead};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "A DNS over HTTPS proxy with ad-blocking features."
)]
struct Args {
    /// Path to the SQLite database file for the blocklist and statistics.
    #[arg(short, long, default_value = "doh_blocklist.db")]
    db_path: PathBuf,

    /// Import a blocklist from a local file.
    #[arg(short, long, value_name = "FILE")]
    blocklist: Option<PathBuf>,

    /// Clear all domains from the blocklist database.
    #[arg(long)]
    clear: bool,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Servers = &'static [(&'static str, &'static str)];

const DOH_SERVERS: Servers = &[
    ("Google", "https://8.8.8.8/dns-query"),
    ("Cloudflare", "https://1.1.1.1/dns-query"),
    ("Quad9", "https://9.9.9.9/dns-query"),
    ("OpenDNS", "https://208.67.222.222/dns-query"),
    ("Mullvad", "https://194.242.2.2/dns-query"),
];

async fn doh_req(
    client: &Client,
    (name, url): (&'static str, &'static str),
    domain: &str,
    record_type: RecordType,
) -> Result<(Message, &'static str), BoxError> {
    let mut msg = Message::new();
    msg.add_query(Query::query(Name::from_ascii(domain)?, record_type));
    msg.set_recursion_desired(true);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);

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
    db: &Mutex<Connection>,
) -> Result<Message, BoxError> {
    let ((res, name), _) = select_ok(
        servers
            .iter()
            .map(|&s| Box::pin(doh_req(client, s, domain, record_type))),
    )
    .await?;
    println!("{} won", name);

    if let Err(e) = db.lock().unwrap().execute(
        "INSERT INTO fastest_servers (server_name) VALUES (?1)",
        params![name],
    ) {
        eprintln!("Error saving stats: {}", e);
    }

    Ok(res)
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
            timestamp INTEGER NOT NULL DEFAULT (unixepoch())
        );
        CREATE TABLE IF NOT EXISTS blocked_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            timestamp INTEGER NOT NULL DEFAULT (unixepoch())
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
                && stmt.execute(params![host]).is_ok()
            {
                count += 1;
            }
        }
        println!("{} blocklisted domains loaded", count);
    }
    transaction.commit()
}

async fn handle_request(
    data: Vec<u8>,
    src: SocketAddr,
    socket: Arc<UdpSocket>,
    client: Client,
    db: Arc<Mutex<Connection>>,
    servers: Servers,
) -> Result<(), BoxError> {
    let request = Message::from_bytes(&data)?;
    let Some(query) = request.queries().first() else {
        return Ok(());
    };

    let qname = query.name().to_utf8();
    let qtype = query.query_type();
    println!("🔍 Query received: {} {:?}", qname, qtype);

    let domain = qname.trim_end_matches('.');
    let is_blocked = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT 1 FROM blocklist WHERE domain = ?1",
            params![domain],
            |_| Ok(()),
        )
        .is_ok();

    let mut response = if is_blocked {
        println!("Blocked domain: {}", domain);

        if let Err(e) = db.lock().unwrap().execute(
            "INSERT INTO blocked_requests (domain) VALUES (?1)",
            params![domain],
        ) {
            eprintln!("Error saving blocked request: {}", e);
        }

        let mut response = Message::new();
        response.set_recursion_desired(true);
        response.set_op_code(OpCode::Query);
        response.set_message_type(MessageType::Response);
        response.add_query(query.clone());
        response.set_response_code(ResponseCode::NoError);

        let rdata = match qtype {
            RecordType::A => Some(RData::A(Ipv4Addr::UNSPECIFIED.into())),
            RecordType::AAAA => {
                Some(RData::AAAA(Ipv6Addr::UNSPECIFIED.into()))
            }
            _ => None,
        };
        if let Some(rdata) = rdata {
            response.add_answer(Record::from_rdata(
                query.name().clone(),
                0,
                rdata,
            ));
        }
        response
    } else {
        match doh_race(&client, servers, &qname, qtype, &db).await {
            Ok(response) => response,
            Err(err) => {
                eprintln!("Error resolving {}: {}", qname, err);
                return Ok(());
            }
        }
    };

    response.set_id(request.id());
    socket.send_to(&response.to_vec()?, src).await?;
    Ok(())
}

fn prepare(args: &Args) -> Result<Option<Connection>, BoxError> {
    let mut conn = setup_database(&args.db_path)?;

    if args.clear {
        conn.execute("DELETE FROM blocklist", ())?;
        println!("Blocklist cleared.");
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

async fn serve(
    socket: UdpSocket,
    conn: Connection,
    servers: Servers,
) -> Result<(), BoxError> {
    let socket = Arc::new(socket);
    let db = Arc::new(Mutex::new(conn));
    let client = Client::new();
    println!("DNS server started");

    loop {
        let mut buf = [0u8; 512];
        let (size, src) = socket.recv_from(&mut buf).await?;
        let data = buf[..size].to_vec();
        let (socket, client, db) =
            (Arc::clone(&socket), client.clone(), Arc::clone(&db));

        tokio::spawn(async move {
            if let Err(e) =
                handle_request(data, src, socket, client, db, servers).await
            {
                eprintln!("Error handling request: {}", e);
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let Some(conn) = prepare(&Args::parse())? else {
        return Ok(());
    };
    serve(UdpSocket::bind("127.0.0.1:53").await?, conn, DOH_SERVERS).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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

    fn count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), (), |r| {
            r.get(0)
        })
        .unwrap()
    }

    /// URL de un puerto TCP cerrado: cualquier request falla con conexión rechazada.
    fn dead_url() -> &'static str {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url =
            format!("http://{}/dns-query", listener.local_addr().unwrap());
        Box::leak(url.into_boxed_str())
    }

    /// Servidor DoH mínimo: responde cada query con un registro A fijo.
    async fn mock_doh(answer: Ipv4Addr) -> &'static str {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url =
            format!("http://{}/dns-query", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
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
                    res.set_message_type(MessageType::Response);
                    let name = res.queries()[0].name().clone();
                    res.add_answer(Record::from_rdata(
                        name,
                        60,
                        RData::A(answer.into()),
                    ));
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
        Box::leak(url.into_boxed_str())
    }

    async fn start(conn: Connection, servers: Servers) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(serve(socket, conn, servers));
        addr
    }

    async fn send_raw(addr: SocketAddr, data: &[u8]) -> Option<Message> {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(data, addr).await.unwrap();
        let mut buf = [0u8; 512];
        let recv = client.recv_from(&mut buf);
        let (n, _) = tokio::time::timeout(Duration::from_millis(1500), recv)
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
        let mut msg = Message::new();
        msg.set_id(4242);
        msg.add_query(Query::query(Name::from_ascii(domain).unwrap(), qtype));
        send_raw(addr, &msg.to_vec().unwrap()).await
    }

    fn blocked_db(path: &Path) -> Connection {
        let mut conn = setup_database(path).unwrap();
        load_blocklist_from_reader(&mut conn, Cursor::new("ads.example.com"))
            .unwrap();
        conn
    }

    #[test]
    fn load_blocklist_skips_comments_blanks_and_duplicates() {
        let mut conn = setup_database(Path::new(":memory:")).unwrap();
        let input = "# comment\n\n0.0.0.0 ads.example.com\ntracker.example.org\nads.example.com\n";
        load_blocklist_from_reader(&mut conn, Cursor::new(input)).unwrap();

        let mut stmt = conn
            .prepare("SELECT domain FROM blocklist ORDER BY domain")
            .unwrap();
        let domains: Vec<String> = stmt
            .query_map((), |r| r.get(0))
            .unwrap()
            .map(|d| d.unwrap())
            .collect();
        assert_eq!(domains, ["ads.example.com", "tracker.example.org"]);
    }

    #[test]
    fn prepare_loads_blocklist_then_clear_empties_it() {
        let db_path = temp_path("prepare.db");
        let list_path = temp_path("list.txt");
        std::fs::write(&list_path, "a.example.com\nb.example.com\n").unwrap();

        let mut args = Args {
            db_path: db_path.clone(),
            blocklist: Some(list_path),
            clear: false,
        };
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
        let args = Args {
            db_path: PathBuf::from(":memory:"),
            blocklist: Some(temp_path("missing.txt")),
            clear: false,
        };
        assert!(prepare(&args).is_err());
    }

    #[tokio::test]
    async fn race_returns_first_success_and_records_winner() {
        let live = mock_doh(Ipv4Addr::new(1, 2, 3, 4)).await;
        let servers = leak_servers(vec![("Dead", dead_url()), ("Live", live)]);
        let db = Mutex::new(setup_database(Path::new(":memory:")).unwrap());

        let res = doh_race(
            &Client::new(),
            servers,
            "example.com",
            RecordType::A,
            &db,
        )
        .await
        .unwrap();

        assert_eq!(
            res.answers()[0].data(),
            &RData::A(Ipv4Addr::new(1, 2, 3, 4).into())
        );
        let winner: String = db
            .lock()
            .unwrap()
            .query_row("SELECT server_name FROM fastest_servers", (), |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(winner, "Live");
    }

    #[tokio::test]
    async fn race_fails_when_all_servers_fail() {
        let servers = leak_servers(vec![("A", dead_url()), ("B", dead_url())]);
        let db = Mutex::new(setup_database(Path::new(":memory:")).unwrap());
        let res = doh_race(
            &Client::new(),
            servers,
            "example.com",
            RecordType::A,
            &db,
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn race_succeeds_even_if_stats_cannot_be_saved() {
        let live = mock_doh(Ipv4Addr::new(5, 6, 7, 8)).await;
        let servers = leak_servers(vec![("Live", live)]);
        // Base sin tablas: el INSERT de estadísticas falla.
        let db = Mutex::new(Connection::open_in_memory().unwrap());
        let res = doh_race(
            &Client::new(),
            servers,
            "example.com",
            RecordType::A,
            &db,
        )
        .await;
        assert!(res.is_ok());
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
        assert_eq!(a.id(), 4242);
        assert_eq!(a.message_type(), MessageType::Response);
        assert_eq!(
            a.answers()[0].data(),
            &RData::A(Ipv4Addr::UNSPECIFIED.into())
        );

        let aaaa = ask(addr, "ads.example.com.", RecordType::AAAA)
            .await
            .unwrap();
        assert_eq!(
            aaaa.answers()[0].data(),
            &RData::AAAA(Ipv6Addr::UNSPECIFIED.into())
        );

        // Tipos distintos de A/AAAA reciben respuesta vacía en vez de timeout.
        let mx = ask(addr, "ads.example.com.", RecordType::MX).await.unwrap();
        assert_eq!(mx.response_code(), ResponseCode::NoError);
        assert!(mx.answers().is_empty());

        let conn = Connection::open(&db_path).unwrap();
        assert_eq!(count(&conn, "blocked_requests"), 3);
    }

    #[tokio::test]
    async fn serve_answers_blocked_even_if_stats_cannot_be_saved() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE blocklist (domain TEXT);
            INSERT INTO blocklist VALUES ('ads.example.com');",
        )
        .unwrap();
        let addr = start(conn, leak_servers(vec![("Dead", dead_url())])).await;
        let res = ask(addr, "ads.example.com.", RecordType::A).await.unwrap();
        assert_eq!(res.answers().len(), 1);
    }

    #[tokio::test]
    async fn serve_forwards_allowed_domains_to_doh() {
        let live = mock_doh(Ipv4Addr::new(9, 9, 9, 9)).await;
        let addr = start(
            blocked_db(&temp_path("serve-forward.db")),
            leak_servers(vec![("Live", live)]),
        )
        .await;

        let res = ask(addr, "good.example.com.", RecordType::A).await.unwrap();
        assert_eq!(res.id(), 4242);
        assert_eq!(
            res.answers()[0].data(),
            &RData::A(Ipv4Addr::new(9, 9, 9, 9).into())
        );
    }

    #[tokio::test]
    async fn serve_ignores_unresolvable_empty_and_malformed_requests() {
        let addr = start(
            setup_database(Path::new(":memory:")).unwrap(),
            leak_servers(vec![("Dead", dead_url())]),
        )
        .await;

        assert!(
            ask(addr, "good.example.com.", RecordType::A)
                .await
                .is_none()
        );
        assert!(
            send_raw(addr, &Message::new().to_vec().unwrap())
                .await
                .is_none()
        );
        assert!(send_raw(addr, &[0xff]).await.is_none());
    }
}

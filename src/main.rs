use chrono::Utc;
use clap::Parser;
use futures::stream::{FuturesUnordered, StreamExt};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType, rdata};
use hickory_proto::serialize::binary::{
    BinDecodable, BinDecoder, BinEncodable, BinEncoder,
};
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
    /// Path to the SQLite database file for the blocklist.
    #[arg(short, long, default_value = "doh_blocklist.db")]
    db_path: PathBuf,

    /// Path to the SQLite database file for statistics.
    #[arg(long, default_value = "doh_stats.db")]
    stats_db_path: PathBuf,

    /// Import a blocklist from a local file.
    #[arg(short, long, value_name = "FILE")]
    blocklist: Option<PathBuf>,

    /// Clear all domains from the blocklist database.
    #[arg(long)]
    clear: bool,
}

struct DOHServer {
    name: &'static str,
    url: &'static str,
}

async fn doh_req(
    client: &Client,
    server: &DOHServer,
    domain: &str,
    record_type: RecordType,
) -> Result<(Message, &'static str), Box<dyn std::error::Error + Send + Sync>>
{
    let mut msg = Message::new();
    let name = Name::from_ascii(&domain)?;
    msg.add_query(Query::query(name, record_type));
    msg.set_recursion_desired(true);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);

    let mut bytes: Vec<u8> = Vec::new();
    {
        let mut encoder = BinEncoder::new(&mut bytes);
        msg.emit(&mut encoder)?;
    }

    let response = client
        .post(server.url)
        .header("Content-Type", "application/dns-message")
        .body(bytes)
        .send()
        .await?
        .bytes()
        .await?;

    let res = Message::from_bytes(&response)?;

    Ok((res, server.name))
}

async fn doh_race(
    client: &Client,
    servers: &Vec<DOHServer>,
    domain: &str,
    record_type: RecordType,
    stats_db: Arc<Mutex<Connection>>,
) -> Result<Message, Box<dyn std::error::Error + Send + Sync>> {
    let mut futures = FuturesUnordered::new();

    for server in servers.iter() {
        futures.push(doh_req(client, server, domain, record_type));
    }

    while let Some(result) = futures.next().await {
        match result {
            Ok((res, name)) => {
                println!("{} won", name);

                let now = Utc::now().timestamp();
                if let Ok(db) = stats_db.lock() {
                    if let Err(e) = db.execute(
                        "INSERT INTO fastest_servers (server_name, timestamp) VALUES (?1, ?2)",
                        params![name, now],
                    ) {
                        eprintln!("Error saving stats: {}", e);
                    }
                }

                return Ok(res);
            }
            Err(_) => continue,
        }
    }

    Err("All servers failed".into())
}

fn setup_database(db_path: &Path) -> Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS blocklist (
            domain TEXT NOT NULL UNIQUE
        )",
        (),
    )?;
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS domain_index ON blocklist (domain)",
        (),
    )?;
    Ok(conn)
}

fn setup_stats_database(db_path: &Path) -> Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS fastest_servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_name TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        )",
        (),
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS blocked_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        )",
        (),
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_fastest_servers_timestamp ON fastest_servers (timestamp)",
        (),
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_blocked_requests_timestamp ON blocked_requests (timestamp)",
        (),
    )?;
    println!("Stats database init: {:?}", db_path);
    Ok(conn)
}

fn clear_blocklist(conn: &Connection) -> Result<()> {
    println!("Cleaning databases");
    conn.execute("DELETE FROM blocklist", ())?;
    println!("Databases cleaned.");
    Ok(())
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
        for line in reader.lines() {
            if let Ok(domain_line) = line {
                if !domain_line.starts_with('#') && !domain_line.is_empty() {
                    if let Some(host) = domain_line.split_whitespace().last() {
                        if stmt.execute(params![host]).is_ok() {
                            count += 1;
                        }
                    }
                }
            }
        }
        println!("{} blocklisted domains loaded", count);
    }

    transaction.commit()?;
    Ok(())
}

async fn handle_request(
    data: Vec<u8>,
    src: SocketAddr,
    socket: Arc<UdpSocket>,
    client: Client,
    doh_servers: Arc<Vec<DOHServer>>,
    blocklist_db: Arc<Mutex<Connection>>,
    stats_db: Arc<Mutex<Connection>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut decoder = BinDecoder::new(&data);
    let request = Message::read(&mut decoder)?;

    if let Some(query) = request.queries().first() {
        let request_id = request.id();
        let qname = query.name().to_utf8();
        let qtype = query.query_type();
        println!("🔍 Query received: {} {:?}", qname, qtype);

        let normalized_qname = qname.trim_end_matches('.').to_string();

        let is_blocked: bool = {
            blocklist_db
                .lock()
                .unwrap()
                .query_row(
                    "SELECT 1 FROM blocklist WHERE domain = ?",
                    params![normalized_qname],
                    |_| Ok(true),
                )
                .unwrap_or(false)
        };

        if is_blocked {
            println!("Blocked domain: {}", normalized_qname);

            let now = Utc::now().timestamp();
            if let Ok(db) = stats_db.lock() {
                if let Err(e) = db.execute(
                    "INSERT INTO blocked_requests (domain, timestamp) VALUES (?1, ?2)",
                    params![normalized_qname, now],
                ) {
                    eprintln!("Error saving blocked request: {}", e);
                }
            }

            let mut response = Message::new();
            response.set_id(request_id);
            response.set_recursion_desired(true);
            response.set_op_code(OpCode::Query);
            response.set_message_type(MessageType::Response);
            response.add_query(query.clone());
            response.set_response_code(ResponseCode::NoError);

            let record = match qtype {
                RecordType::A => {
                    let ip = Ipv4Addr::new(0, 0, 0, 0);
                    Record::from_rdata(
                        query.name().clone(),
                        0,
                        RData::A(rdata::A(ip)),
                    )
                }
                RecordType::AAAA => {
                    let ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
                    Record::from_rdata(
                        query.name().clone(),
                        0,
                        RData::AAAA(rdata::AAAA(ip)),
                    )
                }
                _ => return Ok(()),
            };

            response.add_answer(record);

            let mut response_buf = Vec::new();
            {
                let mut encoder = BinEncoder::new(&mut response_buf);
                response.emit(&mut encoder)?;
            }
            socket.send_to(&response_buf, src).await?;
        } else {
            match doh_race(&client, &doh_servers, &qname, qtype, stats_db)
                .await
            {
                Ok(mut response) => {
                    response.set_id(request_id);
                    let mut response_buf = Vec::new();
                    {
                        let mut encoder = BinEncoder::new(&mut response_buf);
                        response.emit(&mut encoder)?;
                    }

                    socket.send_to(&response_buf, src).await?;
                }
                Err(err) => {
                    eprintln!("Error resolving {}: {}", qname, err);
                }
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    let mut conn = setup_database(&args.db_path)?;
    let conn_stats = setup_stats_database(&args.stats_db_path)?;

    if args.clear {
        clear_blocklist(&conn)?;
        return Ok(());
    }

    if let Some(path) = args.blocklist {
        println!("Loading blocklist from: {:?}", path);
        let file = File::open(&path)?;
        let reader = io::BufReader::new(file);
        load_blocklist_from_reader(&mut conn, reader)?;
    }

    let blocklist_db = Arc::new(Mutex::new(conn));
    let stats_db = Arc::new(Mutex::new(conn_stats));

    let doh_servers = Arc::new(vec![
        DOHServer {
            name: "Google",
            url: "https://8.8.8.8/dns-query",
        },
        DOHServer {
            name: "Cloudflare",
            url: "https://1.1.1.1/dns-query",
        },
        DOHServer {
            name: "Quad9",
            url: "https://9.9.9.9/dns-query",
        },
        DOHServer {
            name: "OpenDNS",
            url: "https://208.67.222.222/dns-query",
        },
        DOHServer {
            name: "Mullvad",
            url: "https://194.242.2.2/dns-query",
        },
    ]);

    let client = Client::new();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:53").await?);
    println!("DNS server started");

    loop {
        let mut buf = [0u8; 512];
        let (size, src) = socket.recv_from(&mut buf).await?;
        let data = buf[..size].to_vec();

        let socket_clone = Arc::clone(&socket);
        let client_clone = client.clone();
        let servers_clone = Arc::clone(&doh_servers);
        let blocklist_db_clone = Arc::clone(&blocklist_db);
        let stats_db_clone = Arc::clone(&stats_db);

        tokio::spawn(async move {
            if let Err(e) = handle_request(
                data,
                src,
                socket_clone,
                client_clone,
                servers_clone,
                blocklist_db_clone,
                stats_db_clone,
            )
            .await
            {
                eprintln!("Error handling request: {}", e);
            }
        });
    }
}

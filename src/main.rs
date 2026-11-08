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

const DOH_SERVERS: &[(&str, &str)] = &[
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
    domain: &str,
    record_type: RecordType,
    db: &Mutex<Connection>,
) -> Result<Message, BoxError> {
    let ((res, name), _) = select_ok(
        DOH_SERVERS
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
        match doh_race(&client, &qname, qtype, &db).await {
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

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    let mut conn = setup_database(&args.db_path)?;

    if args.clear {
        conn.execute("DELETE FROM blocklist", ())?;
        println!("Blocklist cleared.");
        return Ok(());
    }

    if let Some(path) = args.blocklist {
        println!("Loading blocklist from: {:?}", path);
        load_blocklist_from_reader(
            &mut conn,
            io::BufReader::new(File::open(&path)?),
        )?;
    }

    let db = Arc::new(Mutex::new(conn));
    let client = Client::new();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:53").await?);
    println!("DNS server started");

    loop {
        let mut buf = [0u8; 512];
        let (size, src) = socket.recv_from(&mut buf).await?;
        let data = buf[..size].to_vec();
        let (socket, client, db) =
            (Arc::clone(&socket), client.clone(), Arc::clone(&db));

        tokio::spawn(async move {
            if let Err(e) = handle_request(data, src, socket, client, db).await
            {
                eprintln!("Error handling request: {}", e);
            }
        });
    }
}

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
use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "A DNS over HTTPS proxy with ad-blocking features."
)]
struct Args {
    /// Path to the SQLite database file.
    #[arg(short, long, default_value = "doh_blocklist.db")]
    db_path: PathBuf,

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
) -> Result<(Message, &'static str), Box<dyn std::error::Error>> {
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
) -> Result<Message, Box<dyn std::error::Error>> {
    let mut futures = FuturesUnordered::new();

    for server in servers.iter() {
        futures.push(doh_req(client, server, domain, record_type));
    }

    while let Some(result) = futures.next().await {
        match result {
            Ok((res, name)) => {
                println!("{} ganó", name);
                return Ok(res);
            }
            Err(_) => continue,
        }
    }

    Err("Todos los servidores fallaron".into())
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

fn clear_blocklist(conn: &Connection) -> Result<()> {
    println!("Limpiando la base de datos...");
    conn.execute("DELETE FROM blocklist", ())?;
    println!("Base de datos limpiada.");
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
        println!("Cargados {} dominios en la lista de bloqueo.", count);
    }

    transaction.commit()?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut conn = setup_database(&args.db_path)?;

    if args.clear {
        clear_blocklist(&conn)?;
        return Ok(());
    }

    if let Some(path) = args.blocklist {
        println!("Cargando lista de bloqueo desde: {:?}", path);
        let file = File::open(&path)?;
        let reader = io::BufReader::new(file);
        load_blocklist_from_reader(&mut conn, reader)?;
    }

    let doh_servers = vec![
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
    ];
    let client = Client::new();
    let socket = UdpSocket::bind("127.0.0.1:53")?;
    let mut buf = [0u8; 512];

    loop {
        let (size, src) = socket.recv_from(&mut buf)?;
        let data = &buf[..size];

        let mut decoder = BinDecoder::new(data);
        let request = Message::read(&mut decoder)?;

        if let Some(query) = request.queries().first() {
            let request_id = request.id();
            let qname = query.name().to_utf8();
            let qtype = query.query_type();
            println!("🔍 Query recibida: {} {:?}", qname, qtype);

            let normalized_qname = qname.trim_end_matches('.');

            let is_blocked: bool = conn
                .query_row(
                    "SELECT 1 FROM blocklist WHERE domain = ?",
                    params![normalized_qname],
                    |_| Ok(true),
                )
                .unwrap_or(false);

            if is_blocked {
                println!("🚫 Bloqueando dominio: {}", normalized_qname);

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
                    _ => continue,
                };

                response.add_answer(record);

                let mut response_buf = Vec::new();
                {
                    let mut encoder = BinEncoder::new(&mut response_buf);
                    response.emit(&mut encoder)?;
                }
                socket.send_to(&response_buf, src)?;
            } else {
                match doh_race(&client, &doh_servers, &qname, qtype).await {
                    Ok(mut response) => {
                        response.set_id(request_id);
                        let mut response_buf = Vec::new();
                        {
                            let mut encoder =
                                BinEncoder::new(&mut response_buf);
                            response.emit(&mut encoder)?;
                        }

                        socket.send_to(&response_buf, src)?;
                    }
                    Err(err) => {
                        eprintln!("Error resolviendo {}: {}", qname, err);
                    }
                }
            }
        }
    }
}

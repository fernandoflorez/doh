use std::net::UdpSocket;

use futures::stream::{FuturesUnordered, StreamExt};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use hickory_proto::serialize::binary::{BinDecoder, BinEncodable, BinEncoder};
use reqwest::Client;

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

            match doh_race(&client, &doh_servers, &qname, qtype).await {
                Ok(mut response) => {
                    response.set_id(request_id);
                    let mut response_buf = Vec::new();
                    {
                        let mut encoder = BinEncoder::new(&mut response_buf);
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

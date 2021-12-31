use clap::{App, Arg};
use std::net::{UdpSocket, SocketAddr};
use std::time::Duration;

const QTYPE_A: u16 = 0x01;

fn to_type_str(type_val: u16) -> &'static str {
    match type_val {
        1 => "A",
        2 => "NS",
        3 => "MD",
        4 => "MF",
        5 => "CNAME",
        6 => "SOA",
        7 => "MB",
        8 => "MG",
        9 => "MR",
        10 => "NULL",
        11 => "WKS",
        12 => "PTR",
        13 => "HINFO",
        14 => "MINFO",
        15 => "MX",
        16 => "TXT",
        _ => "?"
    }
}

fn to_class_str(class_val: u16) -> &'static str {
    match class_val {
        1 => "IN",
        2 => "CS",
        3 => "CH",
        4 => "HS",
        _ => "?"
    }
}

fn gen_dns_query_header(data: &mut Vec<u8>, id: u16) {
    let qdcount = 1;
    let rd = 1;

    data.push((id >> 8) as u8);
    data.push((id & 0xff) as u8);

    data.push(rd);
    data.push(0);

    data.push((qdcount >> 8) as u8);
    data.push((qdcount & 0xff) as u8);

    data.push(0);
    data.push(0);

    data.push(0);
    data.push(0);

    data.push(0);
    data.push(0);
}

fn gen_dns_query_payload(data: &mut Vec<u8>, host: &str) {
    let qtype: u16 = QTYPE_A;
    let qclass: u16 = 0x01;
    
    for label in host.split(".") {
        data.push(label.len() as u8);

        for &c in label.as_bytes() {
            data.push(c);
        }
    }
    data.push(0x00);

    data.push((qtype >> 8) as u8);
    data.push((qtype & 0xFF) as u8);

    data.push((qclass >> 8) as u8);
    data.push((qclass & 0xFF) as u8);
}

fn parse_name(data: &[u8], i: usize, vec: &mut Vec<u8>) -> usize {
    let mut i = i;
    let mut l: usize;
    loop {
        l = data[i] as usize;
        if l == 0 {
            i += 1;
            break;
        } else if (l >> 6) == 0b11 {
            let offset = ((l & 0b00111111) as u16) << 8 | data[i+1] as u16;
            parse_name(data, offset as usize, vec);
            return i + 2
        } else if vec.len() > 0 {
            vec.push('.' as u8);
        }

        let s = i + 1;
        let e = s + l;
        for &s in data[s..e].iter() {
            vec.push(s);
        }
        i = e;
    }

    i
}

fn parse_ip_v4(data: &[u8], i: usize, vec: &mut Vec<u8>) -> usize {

    for &b in data[i].to_string().as_bytes() {
        vec.push(b);
    }
    vec.push('.' as u8);
    for &b in data[i+1].to_string().as_bytes() {
        vec.push(b);
    }
    vec.push('.' as u8);
    for &b in data[i+2].to_string().as_bytes() {
        vec.push(b);
    }
    vec.push('.' as u8);
    for &b in data[i+3].to_string().as_bytes() {
        vec.push(b);
    }

    i + 4
}

fn parse_question(data: &[u8], i: usize) -> usize {
    let mut vec = vec![];
    let i = parse_name(data, i, &mut vec);
    //println!("question: {}", String::from_utf8(vec).unwrap());
    //let qtype = (data[i] as u16) << 8 | (data[i+1] as u16);
    //let qclass = (data[i+2] as u16) << 8 | (data[i+3] as u16);
    //println!("qtype: {}, qclass: {}", qtype, qclass);
    i + 4
}

fn parse_resource(data: &[u8], i: usize, ip: bool) -> usize {
    let mut vec = vec![];
    let mut i = parse_name(data, i, &mut vec);

    let rtype = (data[i] as u16) << 8 | data[i+1] as u16;
    i+= 2;

    let rclass = (data[i] as u16) << 8 | data[i+1] as u16;
    i+= 2;

    let ttl = (data[i] as u32) << 24
        | (data[i+1] as u32) << 16
        | (data[i+2] as u32) << 8
        | (data[i+3] as u32);
    i += 4;

    let rdlength = (data[i] as u16) << 8 | data[i+1] as u16;
    i+= 2;

    let mut rdata = vec![];
    if ip {
        parse_ip_v4(data, i, &mut rdata);
    } else {
        parse_name(data, i, &mut rdata);
    }
  
    println!("{} -> {}",
        String::from_utf8(vec).unwrap(),
        String::from_utf8(rdata).unwrap());

    println!("  type: {}  class: {}, ttl: {}",
        to_type_str(rtype),
        to_class_str(rclass),
        ttl);

    i += rdlength as usize;

    i
}
fn parse_response(data: &[u8]) {
    let id = (data[0] as u16) << 8 | data[1] as u16;
    assert_eq!(id, 1);

    assert_eq!(data[2] >> 7, 0x1);

    let qdcount = (data[4] as u16) << 8 | data[5] as u16;
    let ancount = (data[6] as u16) << 8 | data[7] as u16;
    let nscount = (data[8] as u16) << 8 | data[9] as u16;
    let arcount = (data[10] as u16) << 8 | data[11] as u16;
    assert_eq!(arcount, 0);

    let mut i = 12_usize;
    for _ in 0..qdcount {
        i = parse_question(data, i);
    }
    for _ in 0..ancount {
        i = parse_resource(data, i, true);
    }
    for _ in 0..nscount {
        i = parse_resource(data, i, false);
    }

    assert_eq!(i, data.len());
}

fn main() -> Result<(), std::io::Error> {

    let app = App::new("resolve")
        .about("A simple to use DNS resolver")
        .arg(
            Arg::with_name("dns-server")
                .short("s")
                .default_value("8.8.8.8")
        )
        .arg(
            Arg::with_name("domain-name")
                .required(true)
        ).get_matches();

    let dns_server_raw = app
        .value_of("dns-server")
        .unwrap();
    let dns_server: SocketAddr = format!("{}:53", dns_server_raw)
        .parse()
        .expect("invalid address");

    let domain_name = app.value_of("domain-name").unwrap();

    let mut request_as_bytes: Vec<u8> = Vec::with_capacity(512);
    let mut response_as_bytes: Vec<u8> = vec![0; 512];

    gen_dns_query_header(&mut request_as_bytes, 1);
    gen_dns_query_payload(&mut request_as_bytes,&domain_name);
        
    let timeout = Duration::from_secs(3);

    let socket = UdpSocket::bind("0.0.0.0:10000")
        .expect("couldn't bind to address");
    socket.set_read_timeout(Some(timeout)).unwrap();
    socket.set_nonblocking(false).unwrap();

    socket.send_to(&mut request_as_bytes, dns_server)
        .expect("couldn't send data");

    let (amt, _remote) = socket
        .recv_from(&mut response_as_bytes)
        .expect("timeout reached");

    parse_response(&response_as_bytes[0..amt]);

    return Ok(());
}

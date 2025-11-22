use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use monoio::io::{AsyncReadRentExt, AsyncWriteRent, AsyncWriteRentExt, Splitable};
use monoio::net::udp::UdpSocket;
use monoio::net::{ListenerOpts, TcpListener, TcpStream};

const SOCKS_VER: u8 = 0x05;

const CMD_CONNECT: u8 = 0x01;
// const CMD_BIND: u8 = 0x02;
// const CMD_UDP_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONN_REFUSED: u8 = 0x05;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

async fn read_exact_array<const N: usize>(stream: &mut TcpStream) -> Result<[u8; N]> {
    let buf = vec![0u8; N];
    let (res, buf) = stream.read_exact(buf).await;
    res?;
    buf.try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidData, "unexpected buffer size"))
}

async fn read_exact_vec(stream: &mut TcpStream, len: usize) -> Result<Vec<u8>> {
    let buf = vec![0u8; len];
    let (res, buf) = stream.read_exact(buf).await;
    res?;
    Ok(buf)
}

async fn write_all_buf(stream: &mut TcpStream, buf: Vec<u8>) -> Result<()> {
    let (res, _buf) = stream.write_all(buf).await;
    res?;
    Ok(())
}

struct Config {
    dns_server: SocketAddr,
    ipmap: HashMap<Option<IpAddr>, IpAddr>,
    deny_unmapped: bool,
    tproxy: bool,
}

impl Config {
    fn from_env() -> Self {
        let dns_server =
            env::var("ZEROSOCKS_DNS_SERVER").unwrap_or_else(|_| "1.1.1.1:53".to_owned());
        let dns_server: SocketAddr = dns_server.parse().expect("invalid ZEROSOCKS_DNS_SERVER");
        println!("using dns server: {}", dns_server);

        let mut ipmap = HashMap::new();

        for (k, v) in std::env::vars() {
            if let Some(k) = k.strip_prefix("ZEROSOCKS_IPMAP_") {
                let Some((from, to)): Option<(Option<IpAddr>, IpAddr)> =
                    v.split_once("->").and_then(|x| {
                        Some((
                            if x.0 == "*" {
                                None
                            } else {
                                Some(x.0.parse().ok()?)
                            },
                            x.1.parse().ok()?,
                        ))
                    })
                else {
                    panic!("invalid ipmap '{}': expecting <from>-><to>", k);
                };

                let from = from.map(|x| x.to_canonical());
                let to = to.to_canonical();
                println!(
                    "ipmap '{}': {}->{}",
                    k,
                    from.map(|x| x.to_string()).unwrap_or_else(|| "*".into()),
                    to
                );
                ipmap.insert(from, to);
            }
        }

        let deny_unmapped = std::env::var("ZEROSOCKS_DENY_UNMAPPED").unwrap_or_default() == "1";
        println!("deny_unmapped: {}", deny_unmapped);
        let tproxy = std::env::var("ZEROSOCKS_TPROXY").unwrap_or_default() == "1";
        println!("tproxy: {}", tproxy);
        Self {
            dns_server,
            ipmap,
            deny_unmapped,
            tproxy,
        }
    }

    async fn connect(&self, addr: SocketAddr) -> std::io::Result<TcpStream> {
        let ip = addr.ip().to_canonical();
        let ip = match self.ipmap.get(&Some(ip)) {
            Some(x) => *x,
            None => match self.ipmap.get(&None) {
                Some(x) => *x,
                None => {
                    if self.deny_unmapped {
                        return Err(std::io::ErrorKind::PermissionDenied.into());
                    } else {
                        ip
                    }
                }
            },
        };
        TcpStream::connect(SocketAddr::new(ip, addr.port())).await
    }
}

fn bind_listener(addr: &str, opts: &ListenerOpts, transparent: bool) -> Result<TcpListener> {
    if transparent {
        return bind_tproxy_listener(addr, opts);
    }
    TcpListener::bind_with_config(addr, opts)
}

fn bind_tproxy_listener(addr: &str, opts: &ListenerOpts) -> Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::ToSocketAddrs;

    let addr = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "empty listen address"))?;

    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    if opts.reuse_port {
        socket.set_reuse_port(true)?;
    }
    if opts.reuse_addr {
        socket.set_reuse_address(true)?;
    }
    if let Some(send_buf_size) = opts.send_buf_size {
        socket.set_send_buffer_size(send_buf_size)?;
    }
    if let Some(recv_buf_size) = opts.recv_buf_size {
        socket.set_recv_buffer_size(recv_buf_size)?;
    }

    socket.set_ip_transparent(true)?;

    let sockaddr = socket2::SockAddr::from(addr);
    socket.bind(&sockaddr)?;
    socket.listen(opts.backlog)?;

    let listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(listener)
}

#[monoio::main]
async fn main() -> Result<()> {
    let config = &*Box::leak(Box::new(Config::from_env()));
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:1080".to_string());
    let listener_opts = ListenerOpts::new().reuse_port(true);
    let listener = bind_listener(&addr, &listener_opts, config.tproxy)?;
    let mode = if config.tproxy {
        "tproxy"
    } else {
        "socks5+redir"
    };
    println!("[{}] listening on {}", mode, addr);
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                monoio::spawn(handle_client(config, stream, peer));
            }
            Err(e) => {
                eprintln!("[socks5] accept error: {}", e);
            }
        }
    }
}

async fn handle_client(config: &'static Config, inbound: TcpStream, peer: SocketAddr) {
    if let Err(e) = dispatch_client(config, inbound, peer).await {
        eprintln!("[socks5] {} error: {}", peer, e);
    }
}

async fn dispatch_client(
    config: &'static Config,
    mut inbound: TcpStream,
    peer: SocketAddr,
) -> Result<()> {
    if config.tproxy {
        let target = inbound.local_addr()?;
        if target.ip().is_unspecified() {
            let _ = inbound.shutdown().await;
            return Err(Error::new(
                ErrorKind::Other,
                "missing original destination in TPROXY mode",
            ));
        }
        return transparent_proxy(config, inbound, peer, target, Vec::new()).await;
    }

    if let Some(target) = try_original_dst(&inbound)? {
        return transparent_proxy(config, inbound, peer, target, Vec::new()).await;
    }

    let first_byte = match read_exact_array::<1>(&mut inbound).await {
        Ok([b]) => b,
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
            let _ = inbound.shutdown().await;
            return Ok(());
        }
        Err(e) => {
            let _ = inbound.shutdown().await;
            return Err(e);
        }
    };

    if first_byte != SOCKS_VER {
        let _ = inbound.shutdown().await;
        return Err(Error::new(
            ErrorKind::InvalidData,
            "unexpected protocol without redirect metadata",
        ));
    }

    handshake_and_proxy(config, inbound, first_byte).await
}

async fn handshake_and_proxy(
    config: &'static Config,
    mut inbound: TcpStream,
    ver_byte: u8,
) -> Result<()> {
    if ver_byte != SOCKS_VER {
        let _ = inbound.shutdown().await;
        return Err(Error::new(
            ErrorKind::InvalidData,
            "unsupported socks version",
        ));
    }

    let nmethods = read_exact_array::<1>(&mut inbound).await?[0] as usize;
    if nmethods == 0 {
        let _ = inbound.shutdown().await;
        return Err(Error::new(ErrorKind::InvalidData, "no auth methods"));
    }

    let methods = read_exact_vec(&mut inbound, nmethods).await?;
    if !methods.iter().any(|&m| m == 0x00) {
        let _ = write_all_buf(&mut inbound, vec![SOCKS_VER, 0xFF]).await;
        let _ = inbound.shutdown().await;
        return Err(Error::new(ErrorKind::Other, "no acceptable auth method"));
    }
    write_all_buf(&mut inbound, vec![SOCKS_VER, 0x00]).await?;

    let req_hdr = read_exact_array::<4>(&mut inbound).await?;
    let ver = req_hdr[0];
    let cmd = req_hdr[1];
    let atyp = req_hdr[3];

    if ver != SOCKS_VER {
        let _ = inbound.shutdown().await;
        return Err(Error::new(ErrorKind::InvalidData, "bad version in request"));
    }
    if cmd != CMD_CONNECT {
        let _ = reply(
            &mut inbound,
            REP_CMD_NOT_SUPPORTED,
            SocketAddr::from(([0, 0, 0, 0], 0)),
        )
        .await;
        let _ = inbound.shutdown().await;
        return Err(Error::new(ErrorKind::Other, "only CONNECT is supported"));
    }

    let (target_host, target_sockaddr_opt, port) = match atyp {
        ATYP_IPV4 => {
            let ip = read_exact_array::<4>(&mut inbound).await?;
            let port = u16::from_be_bytes(read_exact_array::<2>(&mut inbound).await?);
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port));
            (None, Some(addr), port)
        }
        ATYP_DOMAIN => {
            let len = read_exact_array::<1>(&mut inbound).await?[0] as usize;
            let host = read_exact_vec(&mut inbound, len).await?;
            let host = String::from_utf8_lossy(&host).into_owned();
            let port = u16::from_be_bytes(read_exact_array::<2>(&mut inbound).await?);
            (Some(host), None, port)
        }
        ATYP_IPV6 => {
            let ip = read_exact_array::<16>(&mut inbound).await?;
            let port = u16::from_be_bytes(read_exact_array::<2>(&mut inbound).await?);
            let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0));
            (None, Some(addr), port)
        }
        _ => {
            let _ = reply(
                &mut inbound,
                REP_ATYP_NOT_SUPPORTED,
                SocketAddr::from(([0, 0, 0, 0], 0)),
            )
            .await;
            let _ = inbound.shutdown().await;
            return Err(Error::new(
                ErrorKind::InvalidData,
                "address type not supported",
            ));
        }
    };

    let outbound_res: Result<TcpStream> = if let Some(addr) = target_sockaddr_opt {
        config.connect(addr).await
    } else if let Ok(x) = target_host.as_ref().unwrap().parse::<Ipv4Addr>() {
        config.connect(SocketAddrV4::new(x, port).into()).await
    } else {
        let host = target_host.unwrap();
        let ips = resolve_ipv4_a(config, &host).await?;
        let ip = ips
            .into_iter()
            .next()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "no A records"))?;
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
        config.connect(addr).await
    };

    let outbound = match outbound_res {
        Ok(s) => s,
        Err(e) => {
            let code = match e.kind() {
                ErrorKind::ConnectionRefused => REP_CONN_REFUSED,
                ErrorKind::NotFound => REP_HOST_UNREACHABLE,
                ErrorKind::AddrNotAvailable | ErrorKind::AddrInUse => REP_NETWORK_UNREACHABLE,
                _ => REP_GENERAL_FAILURE,
            };
            let _ = reply(&mut inbound, code, SocketAddr::from(([0, 0, 0, 0], 0))).await;
            let _ = inbound.shutdown().await;
            return Err(e);
        }
    };

    let bnd = outbound
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    reply(&mut inbound, REP_SUCCEEDED, bnd).await?;

    let (mut ri, mut wi) = inbound.into_split();
    let (mut ro, mut wo) = outbound.into_split();

    monoio::select! {
        _ = monoio::io::copy(&mut ri, &mut wo) => {}
        _ = monoio::io::copy(&mut ro, &mut wi) => {}
    }

    Ok(())
}

async fn transparent_proxy(
    config: &'static Config,
    mut inbound: TcpStream,
    peer: SocketAddr,
    target: SocketAddr,
    initial_data: Vec<u8>,
) -> Result<()> {
    println!("[transparent] {} -> {}", peer, target);

    let mut outbound = match config.connect(target).await {
        Ok(s) => s,
        Err(e) => {
            let _ = inbound.shutdown().await;
            return Err(e);
        }
    };

    if !initial_data.is_empty() {
        let (res, _) = outbound.write_all(initial_data).await;
        res?;
    }

    let (mut ri, mut wi) = inbound.into_split();
    let (mut ro, mut wo) = outbound.into_split();

    monoio::select! {
        _ = monoio::io::copy(&mut ri, &mut wo) => {}
        _ = monoio::io::copy(&mut ro, &mut wi) => {}
    }

    Ok(())
}

fn try_original_dst(stream: &TcpStream) -> Result<Option<SocketAddr>> {
    use std::mem::ManuallyDrop;
    use std::os::fd::{AsRawFd, FromRawFd};

    use socket2::{SockAddr, Socket};

    // Borrow the raw fd via socket2 without taking ownership of the descriptor.
    let raw_fd = stream.as_raw_fd();
    let socket = unsafe { ManuallyDrop::new(Socket::from_raw_fd(raw_fd)) };
    let dst = match socket.original_dst() {
        Ok(addr) => Ok(addr),
        Err(err) => match err.raw_os_error() {
            Some(code)
                if code == libc::ENOPROTOOPT
                    || code == libc::EOPNOTSUPP
                    || code == libc::EINVAL =>
            {
                socket.original_dst_ipv6()
            }
            Some(libc::ENOENT) => return Ok(None),
            _ => Err(err),
        },
    };

    let dst: SockAddr = match dst {
        Ok(addr) => addr,
        Err(err) => match err.raw_os_error() {
            Some(code)
                if code == libc::ENOPROTOOPT
                    || code == libc::EOPNOTSUPP
                    || code == libc::ENOENT =>
            {
                return Ok(None);
            }
            _ => return Err(err),
        },
    };

    let target = match dst.as_socket() {
        Some(addr) => addr,
        None => {
            return Err(Error::new(
                ErrorKind::Other,
                "unsupported original destination address family",
            ));
        }
    };

    let local = stream.local_addr()?;
    if target == local {
        Ok(None)
    } else {
        Ok(Some(target))
    }
}

async fn reply(stream: &mut TcpStream, rep: u8, bnd: SocketAddr) -> Result<()> {
    // VER REP RSV ATYP BND.ADDR BND.PORT
    let mut buf = Vec::with_capacity(4 + 1 + 16 + 2);
    buf.push(SOCKS_VER);
    buf.push(rep);
    buf.push(0x00);
    match bnd {
        SocketAddr::V4(v4) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    write_all_buf(stream, buf).await?;
    Ok(())
}

// -------------------------------
// Minimal IPv4-only DNS resolver
// -------------------------------
async fn resolve_ipv4_a(config: &'static Config, domain: &str) -> Result<Vec<Ipv4Addr>> {
    // Build query
    // Header: ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
    let id: u16 = 0x1234; // static id is fine for a simple single-query resolver
    let flags: u16 = 0x0100; // recursion desired
    let qdcount: u16 = 1;
    let ancount: u16 = 0;
    let nscount: u16 = 0;
    let arcount: u16 = 0;

    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&qdcount.to_be_bytes());
    buf.extend_from_slice(&ancount.to_be_bytes());
    buf.extend_from_slice(&nscount.to_be_bytes());
    buf.extend_from_slice(&arcount.to_be_bytes());

    // QNAME
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid DNS name"));
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // end of QNAME

    // QTYPE=A(1), QCLASS=IN(1)
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());

    // Send/recv over UDP using monoio
    let sock = UdpSocket::bind("[::]:0")?;
    let (send_res, _) = sock.send_to(buf, config.dns_server).await;
    send_res?;

    let resp_buf = vec![0u8; 512];
    let (recv_res, mut resp) =
        match monoio::time::timeout(Duration::from_secs(5), sock.recv_from(resp_buf)).await {
            Ok(x) => x,
            Err(_) => return Err(std::io::ErrorKind::TimedOut.into()),
        };
    let (n, _) = recv_res?;
    resp.truncate(n);

    parse_dns_a_response(&resp, id)
}

// Parse a minimal DNS response and collect A records.
// Very small parser: enough for common cases (handles pointers in NAME via first-byte check).
fn parse_dns_a_response(pkt: &[u8], expect_id: u16) -> Result<Vec<Ipv4Addr>> {
    if pkt.len() < 12 {
        return Err(Error::new(ErrorKind::InvalidData, "short DNS header"));
    }

    let id = u16::from_be_bytes([pkt[0], pkt[1]]);
    if id != expect_id {
        return Err(Error::new(ErrorKind::InvalidData, "mismatched DNS id"));
    }

    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    let rcode = (flags & 0x000F) as u8;
    if rcode != 0 {
        return Err(Error::new(
            ErrorKind::Other,
            format!("dns error rcode={}", rcode),
        ));
    }

    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    // let nscount = u16::from_be_bytes([pkt[8], pkt[9]]) as usize;
    // let arcount = u16::from_be_bytes([pkt[10], pkt[11]]) as usize;

    let mut off = 12;

    // Skip questions
    for _ in 0..qdcount {
        off = skip_name(pkt, off)?;
        // QTYPE + QCLASS
        off = off
            .checked_add(4)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "overflow"))?;
        if off > pkt.len() {
            return Err(Error::new(ErrorKind::InvalidData, "short question"));
        }
    }

    // Answers
    let mut addrs = Vec::new();
    for _ in 0..ancount {
        off = skip_name(pkt, off)?;
        if off + 10 > pkt.len() {
            return Err(Error::new(ErrorKind::InvalidData, "short rr header"));
        }
        let typ = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
        let cls = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
        // ttl: [off+4..off+8]
        let rdlen = u16::from_be_bytes([pkt[off + 8], pkt[off + 9]]) as usize;
        off += 10;

        if off + rdlen > pkt.len() {
            return Err(Error::new(ErrorKind::InvalidData, "short rdata"));
        }

        if typ == 1 && cls == 1 && rdlen == 4 {
            let a = Ipv4Addr::new(pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]);
            addrs.push(a);
        }
        off += rdlen;
    }

    Ok(addrs)
}

// Skip a NAME field at offset `off`.
// Handles:
// - sequence of labels ending with 0x00, or
// - compression pointer (first two bits 11: 0xC0..), consuming 2 bytes.
// Returns new offset after the NAME.
fn skip_name(pkt: &[u8], mut off: usize) -> Result<usize> {
    if off >= pkt.len() {
        return Err(Error::new(ErrorKind::InvalidData, "bad name offset"));
    }
    let _start = off;
    let mut jumped = false;
    let mut _seen = 0usize;

    loop {
        if off >= pkt.len() {
            return Err(Error::new(ErrorKind::InvalidData, "unterminated name"));
        }
        let len = pkt[off];
        if len & 0xC0 == 0xC0 {
            // pointer: 2 bytes
            if off + 1 >= pkt.len() {
                return Err(Error::new(ErrorKind::InvalidData, "truncated pointer"));
            }
            off += 2;
            jumped = true;
            break;
        } else if len == 0 {
            off += 1;
            break;
        } else {
            let l = len as usize;
            if off + 1 + l > pkt.len() {
                return Err(Error::new(ErrorKind::InvalidData, "label overruns packet"));
            }
            off += 1 + l;
            _seen += 1;
            if _seen > 128 {
                return Err(Error::new(ErrorKind::InvalidData, "too many labels"));
            }
        }
    }

    if jumped {
        // When a pointer is used, the NAME ends at the pointer bytes in the message being parsed,
        // so the caller's offset should be right after those two bytes.
        Ok(off)
    } else {
        Ok(off)
    }
}

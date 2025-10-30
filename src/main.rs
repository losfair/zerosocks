// Simple single-file SOCKS5 (RFC 1928) proxy using monoio (io_uring)
// - Auth: NO AUTH (0x00)
// - Command: CONNECT
// - Address types: IPv4/IPv6/DOMAIN
// - DNS: simple IPv4-only A-record resolver over UDP to 1.1.1.1
//
// Build quickstart:
//   cargo new socks5-monoio && cd socks5-monoio
//   # Replace src/main.rs with this file
//   # Cargo.toml:
//   # [dependencies]
//   # monoio = { version = "0.2", features = ["macros", "net", "time"] }
//   cargo run --release -- 0.0.0.0:1080
//
// Notes:
// - The DNS client is intentionally minimal: it does one UDP query to 1.1.1.1,
//   parses A records, and picks the first IPv4 address. No retries, no timeout,
//   limited name compression handling (enough for typical answers).
// - For production, add timeouts/retries, better parsing, CNAME chasing,
//   and more robust error handling.

use std::convert::TryInto;
use std::env;
use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use monoio::io::{AsyncReadRentExt, AsyncWriteRent, AsyncWriteRentExt, Splitable};
use monoio::net::udp::UdpSocket;
use monoio::net::{TcpListener, TcpStream};

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

#[monoio::main]
async fn main() -> Result<()> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:1080".to_string());
    println!("[socks5] listening on {}", addr);

    let listener = TcpListener::bind(addr)?;
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                monoio::spawn(handle_client(stream, peer));
            }
            Err(e) => {
                eprintln!("[socks5] accept error: {}", e);
            }
        }
    }
}

async fn handle_client(inbound: TcpStream, peer: SocketAddr) {
    if let Err(e) = dispatch_client(inbound, peer).await {
        eprintln!("[socks5] {} error: {}", peer, e);
    }
}

async fn dispatch_client(mut inbound: TcpStream, peer: SocketAddr) -> Result<()> {
    if let Some(target) = try_original_dst(&inbound)? {
        return transparent_proxy(inbound, peer, target, Vec::new()).await;
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

    handshake_and_proxy(inbound, first_byte).await
}

async fn handshake_and_proxy(mut inbound: TcpStream, ver_byte: u8) -> Result<()> {
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
        TcpStream::connect(addr).await
    } else {
        let host = target_host.unwrap();
        let ips = resolve_ipv4_a(&host).await?;
        let ip = ips
            .into_iter()
            .next()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "no A records"))?;
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
        TcpStream::connect(addr).await
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
    mut inbound: TcpStream,
    peer: SocketAddr,
    target: SocketAddr,
    initial_data: Vec<u8>,
) -> Result<()> {
    println!("[redir] {} -> {}", peer, target);

    let mut outbound = match TcpStream::connect(target).await {
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

#[cfg(target_os = "linux")]
const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

#[cfg(target_os = "linux")]
fn try_original_dst(stream: &TcpStream) -> Result<Option<SocketAddr>> {
    use std::os::fd::AsRawFd;

    unsafe {
        let fd = stream.as_raw_fd();
        let mut addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        let mut ret = libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut _,
            &mut len,
        );

        if ret != 0 {
            let err = Error::last_os_error();
            match err.raw_os_error() {
                Some(code)
                    if code == libc::ENOPROTOOPT
                        || code == libc::EOPNOTSUPP
                        || code == libc::EINVAL =>
                {
                    ret = libc::getsockopt(
                        fd,
                        libc::SOL_IPV6,
                        IP6T_SO_ORIGINAL_DST,
                        &mut addr as *mut _ as *mut _,
                        &mut len,
                    );
                    if ret != 0 {
                        let err = Error::last_os_error();
                        match err.raw_os_error() {
                            Some(code)
                                if code == libc::ENOPROTOOPT
                                    || code == libc::EOPNOTSUPP
                                    || code == libc::ENOENT =>
                            {
                                return Ok(None);
                            }
                            _ => return Err(err),
                        }
                    }
                }
                Some(libc::ENOENT) => return Ok(None),
                _ => return Err(err),
            }
        }

        let target = sockaddr_storage_to_addr(&addr)?;
        let local = stream.local_addr()?;
        if target == local {
            Ok(None)
        } else {
            Ok(Some(target))
        }
    }
}

#[cfg(target_os = "linux")]
fn sockaddr_storage_to_addr(storage: &libc::sockaddr_storage) -> Result<SocketAddr> {
    unsafe {
        match storage.ss_family as i32 {
            libc::AF_INET => {
                let sin = *(storage as *const _ as *const libc::sockaddr_in);
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                let port = u16::from_be(sin.sin_port);
                Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            }
            libc::AF_INET6 => {
                let sin6 = *(storage as *const _ as *const libc::sockaddr_in6);
                let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                let port = u16::from_be(sin6.sin6_port);
                let flowinfo = u32::from_be(sin6.sin6_flowinfo);
                let scope_id = sin6.sin6_scope_id;
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    ip, port, flowinfo, scope_id,
                )))
            }
            _ => Err(Error::new(
                ErrorKind::Other,
                "unsupported original destination address family",
            )),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn try_original_dst(_stream: &TcpStream) -> Result<Option<SocketAddr>> {
    Ok(None)
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
const DNS_SERVER: &str = "1.1.1.1:53";

async fn resolve_ipv4_a(domain: &str) -> Result<Vec<Ipv4Addr>> {
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
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let server: SocketAddr = DNS_SERVER
        .parse()
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid DNS server address"))?;
    let (send_res, _) = sock.send_to(buf, server).await;
    send_res?;

    let resp_buf = vec![0u8; 512];
    let (recv_res, mut resp) = sock.recv_from(resp_buf).await;
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

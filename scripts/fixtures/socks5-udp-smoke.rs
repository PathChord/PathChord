use std::env;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

fn read_exact(stream: &mut TcpStream, length: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes).expect("SOCKS5 response");
    bytes
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let proxy_port: u16 = args[1].parse().expect("proxy port");
    let target_port: u16 = args[2].parse().expect("target port");
    let payload = b"udp-role-smoke";
    let mut control = TcpStream::connect(("127.0.0.1", proxy_port)).expect("SOCKS5 control");
    control
        .write_all(&[5, 1, 0])
        .expect("SOCKS5 greeting");
    assert_eq!(read_exact(&mut control, 2), [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .expect("UDP ASSOCIATE");
    let response = read_exact(&mut control, 10);
    assert_eq!(response[1], 0, "UDP ASSOCIATE rejected");
    let relay = SocketAddr::from((
        Ipv4Addr::new(response[4], response[5], response[6], response[7]),
        u16::from_be_bytes([response[8], response[9]]),
    ));
    let udp = UdpSocket::bind("127.0.0.1:0").expect("UDP client");
    udp.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("UDP timeout");
    let mut datagram = vec![0, 0, 0, 1, 127, 0, 0, 1];
    datagram.extend_from_slice(&target_port.to_be_bytes());
    datagram.extend_from_slice(payload);
    udp.send_to(&datagram, relay).expect("UDP relay send");
    let mut response = [0_u8; 2048];
    let (length, _) = udp.recv_from(&mut response).expect("UDP relay response");
    assert!(length >= 10);
    assert_eq!(&response[length - payload.len()..length], payload);
}

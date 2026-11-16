use std::net::UdpSocket;

fn main() {
    let socket = UdpSocket::bind(("127.0.0.1", 18081)).expect("UDP echo bind");
    let mut buffer = [0_u8; 2048];
    let (length, peer) = socket.recv_from(&mut buffer).expect("UDP echo receive");
    socket
        .send_to(&buffer[..length], peer)
        .expect("UDP echo response");
}

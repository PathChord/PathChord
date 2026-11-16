//! Shared helpers for native Shadowsocks methods outside shadowsocks-rust.

use std::collections::{HashSet, VecDeque};
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use md5::{Digest, Md5};
use shadowsocks::relay::socks5::Address;
use zeroize::Zeroizing;

use crate::{Endpoint, TransitError};

pub(super) const NONCE_LEN: usize = 24;
pub(super) const MAX_PACKET: usize = 65_507;
const REPLAY_WINDOW: usize = 4096;

#[derive(Default)]
pub(super) struct Salts {
    set: HashSet<[u8; NONCE_LEN]>,
    order: VecDeque<[u8; NONCE_LEN]>,
}

impl Salts {
    fn insert(&mut self, salt: [u8; NONCE_LEN]) -> bool {
        if !self.set.insert(salt) {
            return false;
        }
        self.order.push_back(salt);
        if self.order.len() > REPLAY_WINDOW {
            let oldest = self.order.pop_front().expect("nonempty replay window");
            self.set.remove(&oldest);
        }
        true
    }
}

pub(super) type SharedSalts = Arc<Mutex<Salts>>;

pub(super) fn remember(salts: &SharedSalts, salt: [u8; NONCE_LEN]) -> bool {
    salts
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(salt)
}

pub(super) fn fresh_salt(salts: &SharedSalts) -> io::Result<[u8; NONCE_LEN]> {
    for _ in 0..4 {
        let mut salt = [0; NONCE_LEN];
        getrandom::fill(&mut salt)
            .map_err(|_| io::Error::other("Shadowsocks randomness failed"))?;
        if remember(salts, salt) {
            return Ok(salt);
        }
    }
    Err(io::Error::other("Shadowsocks salt generation failed"))
}

pub(super) fn master_key<const N: usize>(password: &[u8]) -> Zeroizing<[u8; N]> {
    let mut key = Zeroizing::new([0; N]);
    let mut previous = Zeroizing::new([0; 16]);
    let mut offset = 0;
    while offset < N {
        let mut hash = Md5::new();
        if offset != 0 {
            hash.update(previous.as_slice());
        }
        hash.update(password);
        previous.copy_from_slice(&hash.finalize());
        let length = (N - offset).min(previous.len());
        key[offset..offset + length].copy_from_slice(&previous[..length]);
        offset += length;
    }
    key
}

pub(super) fn connection() -> TransitError {
    TransitError::Connection("Shadowsocks connection failed".into())
}

pub(super) fn protocol(message: &'static str) -> TransitError {
    TransitError::Protocol(message.into())
}

pub(super) fn target_address(destination: &Endpoint) -> Address {
    match destination.host.parse::<IpAddr>() {
        Ok(ip) => Address::SocketAddress((ip, destination.port).into()),
        Err(_) => Address::DomainNameAddress(destination.host.clone(), destination.port),
    }
}

pub(super) fn matches_destination(expected: &Endpoint, received: &Address) -> bool {
    match received {
        Address::SocketAddress(address) => {
            expected.port == address.port()
                && match expected.host.parse::<IpAddr>() {
                    Ok(ip) => ip == address.ip(),
                    Err(_) => true,
                }
        }
        Address::DomainNameAddress(host, port) => {
            expected.port == *port && expected.host.eq_ignore_ascii_case(host)
        }
    }
}

//! Wire-compatible dae/uTLS Android 11 OkHttp ClientHello profile.

use alloc::vec::Vec;

use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::ClientHelloPayload;
use crate::{CipherSuite, Error};

fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(4 + body.len());
    value.extend_from_slice(&kind.to_be_bytes());
    value.extend_from_slice(&(body.len() as u16).to_be_bytes());
    value.extend_from_slice(body);
    value
}

pub(super) fn apply(hello: &mut ClientHelloPayload) -> Result<(), Error> {
    const CIPHERS: [u16; 12] = [
        0xc02b, 0xc02c, 0xcca9, 0xc02f, 0xc030, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
        0x0035,
    ];
    hello.cipher_suites = CIPHERS.into_iter().map(CipherSuite::from).collect();
    let mut extensions = Vec::new();
    let sni = hello
        .extensions
        .encode_for_reality(ExtensionType::ServerName);
    if !sni.is_empty() {
        extensions.push(sni);
    }
    let status = hello
        .extensions
        .encode_for_reality(ExtensionType::StatusRequest);
    if status.is_empty() {
        return Err(Error::General(
            "Android ClientHello is missing status_request".into(),
        ));
    }
    extensions.extend([
        extension(0x0017, &[]),
        extension(0xff01, &[0]),
        extension(0x000a, &[0, 6, 0, 0x1d, 0, 0x17, 0, 0x18]),
        extension(0x000b, &[1, 0]),
        status,
        extension(
            0x000d,
            &[0, 18, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1, 2, 1],
        ),
    ]);
    hello.extensions.reality_extensions = Some(extensions);
    Ok(())
}

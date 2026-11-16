//! Wire-compatible dae/uTLS Firefox 120 ClientHello profile.

use alloc::{vec, vec::Vec};

use crate::crypto::SecureRandom;
use crate::msgs::codec::Codec;
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::ClientHelloPayload;
use crate::{CipherSuite, Error, NamedGroup};

fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(4 + body.len());
    value.extend_from_slice(&kind.to_be_bytes());
    value.extend_from_slice(&(body.len() as u16).to_be_bytes());
    value.extend_from_slice(body);
    value
}

fn required(hello: &ClientHelloPayload, kind: ExtensionType) -> Result<Vec<u8>, Error> {
    let value = hello.extensions.encode_for_reality(kind);
    if value.is_empty() {
        return Err(Error::General(
            "Firefox ClientHello is missing a required extension".into(),
        ));
    }
    Ok(value)
}

pub(super) fn apply(
    hello: &mut ClientHelloPayload,
    random: &dyn SecureRandom,
    ech_key: &[u8],
) -> Result<(), Error> {
    if ech_key.len() != 32 {
        return Err(Error::General("Firefox ECH GREASE key is invalid".into()));
    }
    const CIPHERS: [u16; 17] = [
        0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009,
        0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ];
    hello.cipher_suites = CIPHERS.into_iter().map(CipherSuite::from).collect();

    let shares = hello
        .key_shares
        .as_ref()
        .ok_or_else(|| Error::General("Firefox ClientHello key shares are missing".into()))?;
    if shares.len() != 2
        || shares[0].group != NamedGroup::X25519
        || shares[0].payload.0.len() != 32
        || shares[1].group != NamedGroup::secp256r1
        || shares[1].payload.0.len() != 65
    {
        return Err(Error::General(
            "Firefox ClientHello requires X25519 and P-256 shares".into(),
        ));
    }
    let mut shares_body = Vec::new();
    for share in shares {
        share.encode(&mut shares_body);
    }
    let mut shares_vector = (shares_body.len() as u16).to_be_bytes().to_vec();
    shares_vector.extend_from_slice(&shares_body);

    let mut seed = [0_u8; 2];
    random.fill(&mut seed)?;
    let mut payload = vec![0; 239];
    random.fill(&mut payload)?;
    let mut ech = vec![
        0,
        0,
        1,
        0,
        if seed[0] & 1 == 0 { 1 } else { 3 },
        seed[1],
        0,
        32,
    ];
    ech.extend_from_slice(ech_key);
    ech.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    ech.extend_from_slice(&payload);

    let mut extensions = Vec::new();
    let sni = hello
        .extensions
        .encode_for_reality(ExtensionType::ServerName);
    if !sni.is_empty() {
        extensions.push(sni);
    }
    extensions.extend([
        extension(0x0017, &[]),
        extension(0xff01, &[0]),
        extension(
            0x000a,
            &[0, 12, 0, 0x1d, 0, 0x17, 0, 0x18, 0, 0x19, 1, 0, 1, 1],
        ),
        extension(0x000b, &[1, 0]),
        extension(0x0023, &[]),
        required(hello, ExtensionType::ALProtocolNegotiation)?,
        required(hello, ExtensionType::StatusRequest)?,
        extension(0x0022, &[0, 8, 4, 3, 5, 3, 6, 3, 2, 3]),
        extension(0x0033, &shares_vector),
        extension(0x002b, &[4, 3, 4, 3, 3]),
        extension(
            0x000d,
            &[
                0, 22, 4, 3, 5, 3, 6, 3, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1, 2, 3, 2, 1,
            ],
        ),
        extension(0x002d, &[1, 1]),
        extension(0x001c, &[0x40, 0x01]),
        extension(0xfe0d, &ech),
    ]);
    hello.extensions.reality_extensions = Some(extensions);
    Ok(())
}

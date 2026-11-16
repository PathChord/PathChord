//! REALITY ClientHello profile matching dae's Chrome 133 preset.

use alloc::vec;
use alloc::vec::Vec;

use crate::crypto::SecureRandom;
use crate::msgs::codec::Codec;
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::ClientHelloPayload;
use crate::{CipherSuite, Error, NamedGroup};

fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(4 + body.len());
    encoded.extend_from_slice(&kind.to_be_bytes());
    encoded.extend_from_slice(&(body.len() as u16).to_be_bytes());
    encoded.extend_from_slice(body);
    encoded
}

fn grease(seed: u8) -> u16 {
    let byte = (seed & 0xf0) | 0x0a;
    u16::from_be_bytes([byte, byte])
}

fn required(hello: &ClientHelloPayload, kind: ExtensionType) -> Result<Vec<u8>, Error> {
    let encoded = hello.extensions.encode_for_reality(kind);
    if encoded.is_empty() {
        return Err(Error::General(
            "Chrome REALITY profile is missing a TLS extension".into(),
        ));
    }
    Ok(encoded)
}

/// Freeze all random values and encoded extensions before the REALITY proof is
/// computed, so the proof, handshake transcript, and sent bytes agree.
pub(super) fn apply(
    hello: &mut ClientHelloPayload,
    random: &dyn SecureRandom,
    ech_encapsulated_key: &[u8],
    hybrid: bool,
) -> Result<(), Error> {
    if ech_encapsulated_key.len() != 32 {
        return Err(Error::General(
            "Chrome REALITY ECH GREASE key is invalid".into(),
        ));
    }
    let mut seeds = [0_u8; 6];
    random.fill(&mut seeds)?;
    let cipher_grease = grease(seeds[0]);
    let group_grease = grease(seeds[1]);
    let first_grease = grease(seeds[2]);
    let mut second_grease = grease(seeds[3]);
    if first_grease == second_grease {
        second_grease ^= 0x1010;
    }
    let version_grease = grease(seeds[4]);

    const CIPHERS: [u16; 15] = [
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
        0x009c, 0x009d, 0x002f, 0x0035,
    ];
    hello.cipher_suites = core::iter::once(CipherSuite::from(cipher_grease))
        .chain(CIPHERS.into_iter().map(CipherSuite::from))
        .collect();

    let mut groups = vec![0, if hybrid { 10 } else { 8 }];
    groups.extend_from_slice(&group_grease.to_be_bytes());
    if hybrid {
        groups.extend_from_slice(&[0x11, 0xec]);
    }
    groups.extend_from_slice(&[0, 0x1d, 0, 0x17, 0, 0x18]);

    let mut shares = Vec::new();
    shares.extend_from_slice(&group_grease.to_be_bytes());
    shares.extend_from_slice(&[0, 1, 0]);
    let real_shares = hello
        .key_shares
        .as_ref()
        .ok_or_else(|| Error::General("Chrome REALITY key shares are missing".into()))?;
    let valid = if hybrid {
        real_shares.len() == 2
            && real_shares[0].group == NamedGroup::X25519MLKEM768
            && real_shares[1].group == NamedGroup::X25519
            && real_shares[0].payload.0.len() == 1216
            && real_shares[1].payload.0.len() == 32
            && real_shares[0].payload.0[1184..] != real_shares[1].payload.0[..]
    } else {
        real_shares.len() == 1
            && real_shares[0].group == NamedGroup::X25519
            && real_shares[0].payload.0.len() == 32
    };
    if !valid {
        return Err(Error::General(
            "Chrome REALITY key shares do not match the selected profile".into(),
        ));
    }
    for share in real_shares {
        share.encode(&mut shares);
    }
    let mut share_body = (shares.len() as u16).to_be_bytes().to_vec();
    share_body.extend_from_slice(&shares);

    let mut versions = vec![6];
    versions.extend_from_slice(&version_grease.to_be_bytes());
    versions.extend_from_slice(&[3, 4, 3, 3]);

    // BoringSSL/uTLS GREASE ECH uses X25519 + HKDF-SHA256 + AES-128-GCM;
    // this is a grease extension, not an offer to use real ECH.
    let payload_len = [144_usize, 176, 208, 240][usize::from(seeds[5] & 3)];
    let mut payload = vec![0; payload_len];
    random.fill(&mut payload)?;
    let mut config_id = [0_u8; 1];
    random.fill(&mut config_id)?;
    let mut ech = vec![0, 0, 1, 0, 1, config_id[0], 0, 32];
    ech.extend_from_slice(ech_encapsulated_key);
    ech.extend_from_slice(&(payload_len as u16).to_be_bytes());
    ech.extend_from_slice(&payload);

    let mut extensions = Vec::new();
    let sni = hello
        .extensions
        .encode_for_reality(ExtensionType::ServerName);
    if !sni.is_empty() {
        extensions.push(sni);
    }
    extensions.push(extension(0x0017, &[]));
    extensions.push(extension(0xff01, &[0]));
    extensions.push(extension(0x000a, &groups));
    extensions.push(extension(0x000b, &[1, 0]));
    extensions.push(extension(0x0023, &[]));
    extensions.push(required(hello, ExtensionType::ALProtocolNegotiation)?);
    extensions.push(required(hello, ExtensionType::StatusRequest)?);
    extensions.push(extension(
        0x000d,
        &[0, 16, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1],
    ));
    extensions.push(extension(0x0012, &[]));
    extensions.push(extension(0x0033, &share_body));
    extensions.push(extension(0x002d, &[1, 1]));
    extensions.push(extension(0x002b, &versions));
    extensions.push(extension(0x001b, &[2, 0, 2]));
    extensions.push(extension(0x44cd, &[0, 3, 2, b'h', b'2']));
    extensions.push(extension(0xfe0d, &ech));

    // GREASE extensions remain at the edges, while ordinary extensions are
    // shuffled per connection like the Chrome/uTLS preset.
    for index in (1..extensions.len()).rev() {
        let modulus = index + 1;
        let upper = (u32::from(u16::MAX) + 1) / modulus as u32 * modulus as u32;
        let chosen = loop {
            let value = u32::from(crate::rand::random_u16(random)?);
            if value < upper {
                break value as usize % modulus;
            }
        };
        extensions.swap(index, chosen);
    }
    extensions.insert(0, extension(first_grease, &[]));
    extensions.push(extension(second_grease, &[0]));
    hello.extensions.reality_extensions = Some(extensions);
    Ok(())
}

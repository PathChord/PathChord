//! Wire-compatible dae/uTLS iOS 14 and Safari 16 ClientHello profiles.

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

fn grease(seed: u8) -> u16 {
    let byte = (seed & 0xf0) | 0x0a;
    u16::from_be_bytes([byte, byte])
}

fn required(hello: &ClientHelloPayload, kind: ExtensionType) -> Result<Vec<u8>, Error> {
    let value = hello.extensions.encode_for_reality(kind);
    if value.is_empty() { return Err(Error::General("Apple ClientHello profile is missing a required extension".into())); }
    Ok(value)
}

pub(super) fn apply(hello: &mut ClientHelloPayload, random: &dyn SecureRandom, safari: bool) -> Result<(), Error> {
    let mut seeds = [0_u8; 4];
    random.fill(&mut seeds)?;
    let cipher_grease = grease(seeds[0]);
    let group_grease = grease(seeds[1]);
    let first_grease = grease(seeds[2]);
    let mut second_grease = grease(seeds[3]);
    if first_grease == second_grease { second_grease ^= 0x1010; }
    // uTLS uses separate version and extension GREASE seeds; neither changes
    // the semantic values, but they must remain fixed across encoding passes.
    let version_grease = grease(crate::rand::random_u16(random)? as u8);

    let suites: &[u16] = if safari {
        &[0x1301,0x1302,0x1303,0xc02c,0xc02b,0xcca9,0xc030,0xc02f,0xcca8,0xc00a,0xc009,0xc014,0xc013,0x009d,0x009c,0x0035,0x002f,0xc008,0xc012,0x000a]
    } else {
        &[0x1301,0x1302,0x1303,0xc02c,0xc02b,0xcca9,0xc030,0xc02f,0xcca8,0xc024,0xc023,0xc00a,0xc009,0xc028,0xc027,0xc014,0xc013,0x009d,0x009c,0x003d,0x003c,0x0035,0x002f,0xc008,0xc012,0x000a]
    };
    hello.cipher_suites = core::iter::once(CipherSuite::from(cipher_grease)).chain(suites.iter().copied().map(CipherSuite::from)).collect();
    let real_shares = hello.key_shares.as_ref().ok_or_else(|| Error::General("Apple ClientHello key share is missing".into()))?;
    if real_shares.len() != 1 || real_shares[0].group != NamedGroup::X25519 || real_shares[0].payload.0.len() != 32 {
        return Err(Error::General("Apple ClientHello requires one X25519 key share".into()));
    }
    let mut shares = Vec::new();
    shares.extend_from_slice(&group_grease.to_be_bytes());
    shares.extend_from_slice(&[0, 1, 0]);
    real_shares[0].encode(&mut shares);
    let mut share_body = (shares.len() as u16).to_be_bytes().to_vec();
    share_body.extend_from_slice(&shares);
    let mut groups = vec![0,10];
    groups.extend_from_slice(&group_grease.to_be_bytes());
    groups.extend_from_slice(&[0,0x1d,0,0x17,0,0x18,0,0x19]);
    let mut versions = vec![10];
    versions.extend_from_slice(&version_grease.to_be_bytes());
    versions.extend_from_slice(&[3,4,3,3,3,2,3,1]);
    let signatures = [0,22, 4,3, 8,4, 4,1, 5,3, 2,3, 8,5, 8,5, 5,1, 8,6, 6,1, 2,1];
    let mut extensions = vec![extension(first_grease, &[])];
    let sni = hello.extensions.encode_for_reality(ExtensionType::ServerName);
    if !sni.is_empty() { extensions.push(sni); }
    extensions.extend([
        extension(0x0017, &[]), extension(0xff01, &[0]), extension(0x000a, &groups),
        extension(0x000b, &[1,0]), required(hello, ExtensionType::ALProtocolNegotiation)?,
        required(hello, ExtensionType::StatusRequest)?, extension(0x000d, &signatures),
        extension(0x0012, &[]), extension(0x0033, &share_body), extension(0x002d, &[1,1]),
        extension(0x002b, &versions),
    ]);
    if safari { extensions.push(extension(0x001b, &[2,0,1])); }
    extensions.push(extension(second_grease, &[0]));

    // BoringPaddingStyle pads a ClientHello of 256..511 bytes to 512,
    // counting the four-byte handshake header and all preceding fields.
    let cipher_bytes = hello.cipher_suites.len() * 2;
    let unpadded = 4 + 2 + 32 + 1 + hello.session_id.len + 2 + cipher_bytes + 2 + 2
        + extensions.iter().map(Vec::len).sum::<usize>();
    if (256..512).contains(&unpadded) {
        let remaining = 512 - unpadded;
        let padding = if remaining >= 5 { remaining - 4 } else { 1 };
        extensions.push(extension(0x0015, &vec![0; padding]));
    }
    hello.extensions.reality_extensions = Some(extensions);
    Ok(())
}

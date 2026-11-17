//! Bounded IP fragmentation at the TUN packet boundary.
//!
//! The TCP/IP reactor continues to own transport state. Reassembly completes
//! before listener/source/protected-destination admission, and outbound IP
//! datagrams are split to the real device MTU. This also covers IPv6 fragments,
//! which smoltcp 0.14 does not reassemble on an IP-medium interface.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use smoltcp::wire::{Ipv4Packet, Ipv6Packet};

pub(super) const MAX_PACKET_BYTES: usize = 65_575;
const MAX_FRAGMENTS: usize = 128;
const LIFETIME: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    source: IpAddr,
    target: IpAddr,
    protocol: u8,
    identification: u32,
}

struct Fragment<'a> {
    key: Key,
    offset: usize,
    more: bool,
    header: Vec<u8>,
    payload: &'a [u8],
}

struct Assembly {
    started: Instant,
    header: Option<Vec<u8>>,
    parts: BTreeMap<usize, Vec<u8>>,
    bytes: usize,
    total: Option<usize>,
}

pub(super) struct Reassembler {
    packets: BTreeMap<Key, Assembly>,
    maximum: usize,
}

impl Reassembler {
    pub(super) fn new(maximum: usize) -> Self {
        Self {
            packets: BTreeMap::new(),
            maximum,
        }
    }

    pub(super) fn receive(&mut self, packet: Vec<u8>, now: Instant) -> Result<Option<Vec<u8>>, ()> {
        self.packets
            .retain(|_, value| now.saturating_duration_since(value.started) < LIFETIME);
        let Some(fragment) = parse_fragment(&packet)? else {
            return Ok(Some(packet));
        };
        let end = fragment
            .offset
            .checked_add(fragment.payload.len())
            .ok_or(())?;
        let maximum = if fragment.key.source.is_ipv4() {
            65_535 - fragment.header.len()
        } else {
            65_535
        };
        if fragment.payload.is_empty()
            || end > maximum
            || (fragment.more && fragment.payload.len() % 8 != 0)
        {
            self.packets.remove(&fragment.key);
            return Err(());
        }
        if !self.packets.contains_key(&fragment.key) && self.packets.len() >= self.maximum {
            return Err(());
        }
        let assembly = self
            .packets
            .entry(fragment.key)
            .or_insert_with(|| Assembly {
                started: now,
                header: None,
                parts: BTreeMap::new(),
                bytes: 0,
                total: None,
            });
        let overlaps = assembly
            .parts
            .iter()
            .any(|(start, bytes)| fragment.offset < start + bytes.len() && end > *start);
        if overlaps
            || assembly.parts.len() >= MAX_FRAGMENTS
            || assembly.bytes + fragment.payload.len() > maximum
            || assembly
                .total
                .is_some_and(|total| end > total || (!fragment.more && end != total))
            || (!fragment.more
                && assembly
                    .parts
                    .iter()
                    .any(|(offset, bytes)| offset + bytes.len() > end))
        {
            self.packets.remove(&fragment.key);
            return Err(());
        }
        if fragment.offset == 0 {
            assembly.header = Some(fragment.header);
        }
        if !fragment.more {
            assembly.total = Some(end);
        }
        assembly.bytes += fragment.payload.len();
        assembly
            .parts
            .insert(fragment.offset, fragment.payload.to_vec());
        if assembly.total != Some(assembly.bytes) || assembly.header.is_none() {
            return Ok(None);
        }
        let mut assembly = self.packets.remove(&fragment.key).ok_or(())?;
        let mut result = assembly.header.take().ok_or(())?;
        for part in assembly.parts.into_values() {
            result.extend(part);
        }
        if fragment.key.source.is_ipv4() {
            let length = u16::try_from(result.len()).map_err(|_| ())?;
            result[2..4].copy_from_slice(&length.to_be_bytes());
            result[6..8].fill(0);
            Ipv4Packet::new_unchecked(&mut result).fill_checksum();
        } else {
            let length = u16::try_from(result.len() - 40).map_err(|_| ())?;
            result[4..6].copy_from_slice(&length.to_be_bytes());
            result[6] = fragment.key.protocol;
        }
        Ok(Some(result))
    }
}

pub(super) fn source(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 => Some(IpAddr::V4(Ipv4Packet::new_checked(packet).ok()?.src_addr())),
        6 => Some(IpAddr::V6(Ipv6Packet::new_checked(packet).ok()?.src_addr())),
        _ => None,
    }
}

fn parse_fragment(packet: &[u8]) -> Result<Option<Fragment<'_>>, ()> {
    match packet.first().ok_or(())? >> 4 {
        4 => {
            let ipv4 = Ipv4Packet::new_checked(packet).map_err(|_| ())?;
            if !ipv4.verify_checksum() {
                return Err(());
            }
            let flags = u16::from_be_bytes([packet[6], packet[7]]);
            if flags & 0x3fff == 0 {
                return Ok(None);
            }
            if flags & 0xc000 != 0 {
                return Err(());
            }
            let header_length = usize::from(ipv4.header_len());
            let protocol = packet[9];
            if !matches!(protocol, 6 | 17) {
                return Err(());
            }
            Ok(Some(Fragment {
                key: Key {
                    source: IpAddr::V4(ipv4.src_addr()),
                    target: IpAddr::V4(ipv4.dst_addr()),
                    protocol,
                    identification: u32::from(u16::from_be_bytes([packet[4], packet[5]])),
                },
                offset: usize::from(flags & 0x1fff) * 8,
                more: flags & 0x2000 != 0,
                header: packet[..header_length].to_vec(),
                payload: ipv4.payload(),
            }))
        }
        6 => {
            let ipv6 = Ipv6Packet::new_checked(packet).map_err(|_| ())?;
            if packet[6] != 44 {
                return Ok(None);
            }
            let fragment = ipv6.payload();
            if fragment.len() < 8 || !matches!(fragment[0], 6 | 17) {
                return Err(());
            }
            let flags = u16::from_be_bytes([fragment[2], fragment[3]]);
            if flags & 0x6 != 0 || fragment[1] != 0 {
                return Err(());
            }
            Ok(Some(Fragment {
                key: Key {
                    source: IpAddr::V6(ipv6.src_addr()),
                    target: IpAddr::V6(ipv6.dst_addr()),
                    protocol: fragment[0],
                    identification: u32::from_be_bytes(fragment[4..8].try_into().map_err(|_| ())?),
                },
                offset: usize::from(flags & 0xfff8),
                more: flags & 1 != 0,
                header: packet[..40].to_vec(),
                payload: &fragment[8..],
            }))
        }
        _ => Err(()),
    }
}

pub(super) fn split(packet: &[u8], mtu: usize, identification: u32) -> Result<Vec<Vec<u8>>, ()> {
    if packet.len() <= mtu {
        return Ok(vec![packet.to_vec()]);
    }
    let version = packet.first().ok_or(())? >> 4;
    let header_length = match version {
        4 => usize::from(
            Ipv4Packet::new_checked(packet)
                .map_err(|_| ())?
                .header_len(),
        ),
        6 => {
            Ipv6Packet::new_checked(packet).map_err(|_| ())?;
            40
        }
        _ => return Err(()),
    };
    let overhead = if version == 6 { 8 } else { 0 };
    let chunk_length = mtu.checked_sub(header_length + overhead).ok_or(())? & !7;
    if chunk_length == 0 {
        return Err(());
    }
    let payload = &packet[header_length..];
    let mut fragments = Vec::new();
    for (index, chunk) in payload.chunks(chunk_length).enumerate() {
        let offset = index * chunk_length;
        let more = offset + chunk.len() < payload.len();
        let mut fragment = packet[..header_length].to_vec();
        if version == 4 {
            let length = u16::try_from(header_length + chunk.len()).map_err(|_| ())?;
            fragment[2..4].copy_from_slice(&length.to_be_bytes());
            fragment[4..6].copy_from_slice(&(identification as u16).to_be_bytes());
            let flags =
                (u16::try_from(offset / 8).map_err(|_| ())?) | if more { 0x2000 } else { 0 };
            fragment[6..8].copy_from_slice(&flags.to_be_bytes());
            fragment.extend_from_slice(chunk);
            Ipv4Packet::new_unchecked(&mut fragment).fill_checksum();
        } else {
            let length = u16::try_from(8 + chunk.len()).map_err(|_| ())?;
            fragment[4..6].copy_from_slice(&length.to_be_bytes());
            fragment[6] = 44;
            fragment.extend_from_slice(&[packet[6], 0]);
            let flags = u16::try_from(offset).map_err(|_| ())? | u16::from(more);
            fragment.extend_from_slice(&flags.to_be_bytes());
            fragment.extend_from_slice(&identification.to_be_bytes());
            fragment.extend_from_slice(chunk);
        }
        fragments.push(fragment);
    }
    Ok(fragments)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(version: u8, length: usize) -> Vec<u8> {
        let header = if version == 4 { 20 } else { 40 };
        let mut packet = vec![0; header + length];
        for (index, byte) in packet[header..].iter_mut().enumerate() {
            *byte = index as u8;
        }
        if version == 4 {
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&((header + length) as u16).to_be_bytes());
            packet[8] = 64;
            packet[9] = 17;
            packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
            packet[16..20].copy_from_slice(&[192, 0, 2, 2]);
            Ipv4Packet::new_unchecked(&mut packet).fill_checksum();
        } else {
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&(length as u16).to_be_bytes());
            packet[6] = 17;
            packet[7] = 64;
            packet[23] = 1;
            packet[39] = 2;
        }
        packet
    }

    #[test]
    fn reassembles_reordered_ipv4_and_ipv6_without_losing_datagram_bytes() {
        for version in [4, 6] {
            let packet = packet(version, 4096);
            let fragments = split(&packet, 576, 123).unwrap();
            assert!(fragments.iter().all(|fragment| fragment.len() <= 576));
            let mut assembler = Reassembler::new(2);
            let mut result = None;
            for fragment in fragments.into_iter().rev() {
                result = assembler
                    .receive(fragment, Instant::now())
                    .unwrap()
                    .or(result);
            }
            let result = result.unwrap();
            let header = if version == 4 { 20 } else { 40 };
            assert_eq!(&result[header..], &packet[header..]);
            assert!(assembler.packets.is_empty());
        }
    }

    #[test]
    fn rejects_overlap_and_bounds_incomplete_datagrams_and_lifetime() {
        for version in [4, 6] {
            let now = Instant::now();
            let fragments = split(&packet(version, 4096), 576, 1).unwrap();
            let mut assembler = Reassembler::new(1);
            assert!(
                assembler
                    .receive(fragments[0].clone(), now)
                    .unwrap()
                    .is_none()
            );
            let other = split(&packet(version, 4096), 576, 2).unwrap();
            assert!(assembler.receive(other[0].clone(), now).is_err());
            assert!(assembler.receive(fragments[0].clone(), now).is_err());
            assert!(assembler.packets.is_empty());
            assembler.receive(fragments[0].clone(), now).unwrap();
            assembler.receive(other[0].clone(), now + LIFETIME).unwrap();
            assert_eq!(assembler.packets.len(), 1);
            assert!(assembler.packets.keys().all(|key| key.identification == 2));
        }
    }
}

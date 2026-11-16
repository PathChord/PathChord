//! Bounded, immutable V2Fly geosite and geoip matchers.
//!
//! Databases are decoded from the published protobuf structures. The outer
//! repeated messages are walked with prost's wire decoder one entry at a time,
//! so a small malicious file containing many empty records cannot cause an
//! unbounded allocation before the configured entry limit is enforced.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickKind};
use prost::Message;
use prost::encoding::{
    DecodeContext, WireType, check_wire_type, decode_key, decode_varint, skip_field,
};
use regex::{RegexSet, RegexSetBuilder};
use thiserror::Error;

pub const MAX_DATABASE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_DATABASE_ENTRIES: usize = 3_000_000;
pub const MAX_DATABASE_SETS: usize = 4_096;
pub const MAX_DOMAIN_PATTERN_BYTES: usize = 16_384;
pub const MAX_COMPILED_BYTES: usize = 128 * 1024 * 1024;
const MAX_DECODED_BYTES: usize = 256 * 1024 * 1024;
const MAX_SET_NAME_BYTES: usize = 128;
const MAX_ATTRIBUTE_BYTES: usize = 1024;
const MAX_REGEX_PROGRAM_BYTES: usize = 16 * 1024 * 1024;
const MAX_REGEX_DFA_BYTES: usize = 4 * 1024 * 1024;
const MAX_REGEX_RESERVATION: usize = MAX_REGEX_PROGRAM_BYTES + MAX_REGEX_DFA_BYTES;
const MAX_PLAIN_PATTERN_BYTES: usize = 8 * 1024 * 1024;

/// Errors never contain a database path or pattern contents.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GeodataError {
    #[error("geodata database exceeds the byte limit")]
    DatabaseTooLarge,
    #[error("geodata exceeds the {0} limit")]
    LimitExceeded(&'static str),
    #[error("geodata protobuf is malformed or contains an invalid value")]
    Malformed,
    #[error("geodata contains duplicate set {0}")]
    DuplicateSet(String),
    #[error("invalid geodata set reference")]
    InvalidReference,
    #[error("geodata set {0} is absent")]
    UnknownSet(String),
    #[error("geodata attribute {attribute} is absent in set {set}")]
    UnknownAttribute { set: String, attribute: String },
    #[error("geodata attribute {attribute} in set {set} is not boolean")]
    UnsupportedAttribute { set: String, attribute: String },
    #[error("geodata set {0} contains an unsupported or invalid regular expression")]
    InvalidRegex(String),
}

#[derive(Debug, Clone, Copy)]
struct Limits {
    database_bytes: usize,
    entries: usize,
    sets: usize,
    pattern_bytes: usize,
    decoded_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            database_bytes: MAX_DATABASE_BYTES,
            entries: MAX_DATABASE_ENTRIES,
            sets: MAX_DATABASE_SETS,
            pattern_bytes: MAX_DOMAIN_PATTERN_BYTES,
            decoded_bytes: MAX_DECODED_BYTES,
        }
    }
}

#[derive(Default)]
struct DecodeBudget {
    entries: usize,
    bytes: usize,
}

impl DecodeBudget {
    fn add(&mut self, bytes: usize, limits: Limits) -> Result<(), GeodataError> {
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or(GeodataError::LimitExceeded("entry"))?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or(GeodataError::LimitExceeded("decoded memory"))?;
        if self.entries > limits.entries {
            return Err(GeodataError::LimitExceeded("entry"));
        }
        if self.bytes > limits.decoded_bytes {
            return Err(GeodataError::LimitExceeded("decoded memory"));
        }
        Ok(())
    }
}

/// Use one budget while compiling all selected sets in a policy generation.
/// This bounds aggregate indexes rather than merely bounding each matcher.
#[derive(Debug, Clone)]
pub struct CompileBudget {
    remaining: usize,
}

impl Default for CompileBudget {
    fn default() -> Self {
        Self {
            remaining: MAX_COMPILED_BYTES,
        }
    }
}

impl CompileBudget {
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.remaining
    }

    fn charge(&mut self, amount: usize) -> Result<(), GeodataError> {
        self.remaining = self
            .remaining
            .checked_sub(amount)
            .ok_or(GeodataError::LimitExceeded("compiled memory"))?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AttributeValue {
    Boolean(bool),
    Integer,
}

#[derive(Debug, Clone)]
struct DomainRule {
    kind: u32,
    pattern: String,
    attributes: BTreeMap<String, AttributeValue>,
}

/// A structurally validated, bounded geosite source. It is independent of
/// filesystem paths and can be shared across candidate set compilations.
#[derive(Debug, Clone)]
pub struct GeoSiteDatabase {
    sets: BTreeMap<String, Vec<DomainRule>>,
}

#[derive(Debug, Clone)]
struct GeoIpSet {
    inverse: bool,
    prefixes: Vec<(IpAddr, u8)>,
}

#[derive(Debug, Clone)]
pub struct GeoIpDatabase {
    sets: BTreeMap<String, GeoIpSet>,
}

#[derive(Debug)]
struct SiteMatcherInner {
    full: HashSet<String>,
    roots: HashSet<String>,
    plain: Option<AhoCorasick>,
    regex: Option<RegexSet>,
}

/// Clone shares a compiled, immutable matcher and does not copy its index.
#[derive(Debug, Clone)]
pub struct GeoSiteMatcher(Arc<SiteMatcherInner>);

#[derive(Debug)]
struct IpMatcherInner {
    v4: HashSet<(u32, u8)>,
    v6: HashSet<(u128, u8)>,
    v4_lengths: Vec<u8>,
    v6_lengths: Vec<u8>,
    inverse: bool,
}

#[derive(Debug, Clone)]
pub struct GeoIpMatcher(Arc<IpMatcherInner>);

#[derive(Clone, PartialEq, Message)]
struct ProtoAttribute {
    #[prost(string, tag = "1")]
    key: String,
    #[prost(oneof = "proto_attribute::Value", tags = "2, 3")]
    value: Option<proto_attribute::Value>,
}

mod proto_attribute {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Value {
        #[prost(bool, tag = "2")]
        Boolean(bool),
        #[prost(int64, tag = "3")]
        Integer(i64),
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SET_NAME_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'!'))
}

fn name(value: &str) -> Result<String, GeodataError> {
    if !valid_name(value) {
        return Err(GeodataError::InvalidReference);
    }
    Ok(value.to_ascii_lowercase())
}

fn reference(value: &str) -> Result<(String, Option<String>), GeodataError> {
    let (set, attribute) = value
        .split_once('@')
        .map_or((value, None), |(a, b)| (a, Some(b)));
    Ok((name(set)?, attribute.map(name).transpose()?))
}

fn read_bytes<'a>(wire: WireType, input: &mut &'a [u8]) -> Result<&'a [u8], GeodataError> {
    check_wire_type(WireType::LengthDelimited, wire).map_err(|_| GeodataError::Malformed)?;
    let len = decode_varint(input).map_err(|_| GeodataError::Malformed)?;
    let len = usize::try_from(len).map_err(|_| GeodataError::Malformed)?;
    if len > input.len() {
        return Err(GeodataError::Malformed);
    }
    let (value, rest) = input.split_at(len);
    *input = rest;
    Ok(value)
}

fn read_varint(wire: WireType, input: &mut &[u8]) -> Result<u64, GeodataError> {
    check_wire_type(WireType::Varint, wire).map_err(|_| GeodataError::Malformed)?;
    decode_varint(input).map_err(|_| GeodataError::Malformed)
}

fn skip(wire: WireType, tag: u32, input: &mut &[u8]) -> Result<(), GeodataError> {
    skip_field(wire, tag, input, DecodeContext::default()).map_err(|_| GeodataError::Malformed)
}

fn text(value: &[u8]) -> Result<&str, GeodataError> {
    std::str::from_utf8(value).map_err(|_| GeodataError::Malformed)
}

fn each_field(
    mut input: &[u8],
    mut f: impl FnMut(u32, WireType, &mut &[u8]) -> Result<(), GeodataError>,
) -> Result<(), GeodataError> {
    while !input.is_empty() {
        let (tag, wire) = decode_key(&mut input).map_err(|_| GeodataError::Malformed)?;
        f(tag, wire, &mut input)?;
    }
    Ok(())
}

impl GeoSiteDatabase {
    pub fn decode(bytes: &[u8]) -> Result<Self, GeodataError> {
        Self::decode_with_limits(bytes, Limits::default())
    }

    fn decode_with_limits(bytes: &[u8], limits: Limits) -> Result<Self, GeodataError> {
        if bytes.len() > limits.database_bytes {
            return Err(GeodataError::DatabaseTooLarge);
        }
        let mut budget = DecodeBudget::default();
        let mut sets = BTreeMap::new();
        each_field(bytes, |tag, wire, input| {
            if tag != 1 {
                return skip(wire, tag, input);
            }
            if sets.len() >= limits.sets {
                return Err(GeodataError::LimitExceeded("set"));
            }
            let entry = read_bytes(wire, input)?;
            let mut set_name = None;
            let mut rules = Vec::new();
            each_field(entry, |tag, wire, input| {
                match tag {
                    1 => {
                        set_name = Some(
                            name(text(read_bytes(wire, input)?)?)
                                .map_err(|_| GeodataError::Malformed)?,
                        );
                    }
                    2 => {
                        let raw = read_bytes(wire, input)?;
                        budget.add(raw.len().saturating_add(128), limits)?;
                        rules.push(decode_domain(raw, &mut budget, limits)?);
                    }
                    _ => skip(wire, tag, input)?,
                }
                Ok(())
            })?;
            let set_name = set_name.ok_or(GeodataError::Malformed)?;
            if sets.insert(set_name.clone(), rules).is_some() {
                return Err(GeodataError::DuplicateSet(set_name));
            }
            Ok(())
        })?;
        Ok(Self { sets })
    }

    pub fn compile(&self, value: &str) -> Result<GeoSiteMatcher, GeodataError> {
        self.compile_with_budget(value, &mut CompileBudget::default())
    }

    pub fn compile_with_budget(
        &self,
        value: &str,
        budget: &mut CompileBudget,
    ) -> Result<GeoSiteMatcher, GeodataError> {
        let (set_name, attribute) = reference(value)?;
        let rules = self
            .sets
            .get(&set_name)
            .ok_or_else(|| GeodataError::UnknownSet(set_name.clone()))?;
        let mut full = HashSet::new();
        let mut roots = HashSet::new();
        let mut plain_patterns = Vec::new();
        let mut plain_bytes = 0_usize;
        let mut regex_patterns = Vec::new();
        let mut found_attribute = false;
        let mut staged_budget = budget.clone();
        for rule in rules {
            if let Some(attribute) = attribute.as_ref() {
                match rule.attributes.get(attribute) {
                    None => continue,
                    Some(AttributeValue::Boolean(false)) => {
                        found_attribute = true;
                        continue;
                    }
                    Some(AttributeValue::Boolean(true)) => found_attribute = true,
                    Some(AttributeValue::Integer) => {
                        return Err(GeodataError::UnsupportedAttribute {
                            set: set_name.clone(),
                            attribute: attribute.clone(),
                        });
                    }
                }
            }
            staged_budget.charge(rule.pattern.len().saturating_add(128))?;
            match rule.kind {
                0 => {
                    plain_bytes = plain_bytes.saturating_add(rule.pattern.len());
                    if plain_bytes > MAX_PLAIN_PATTERN_BYTES {
                        return Err(GeodataError::LimitExceeded("plain matcher"));
                    }
                    plain_patterns.push(rule.pattern.to_ascii_lowercase());
                }
                1 => regex_patterns.push(rule.pattern.clone()),
                2 => {
                    roots.insert(rule.pattern.to_ascii_lowercase());
                }
                3 => {
                    full.insert(rule.pattern.to_ascii_lowercase());
                }
                _ => return Err(GeodataError::Malformed),
            }
        }
        if let Some(attribute) = attribute
            && !found_attribute
        {
            return Err(GeodataError::UnknownAttribute {
                set: set_name,
                attribute,
            });
        }
        let plain = if plain_patterns.is_empty() {
            None
        } else {
            // Noncontiguous NFA has a bounded representation per input byte;
            // a DFA can instead grow with patterns times alphabet size.
            staged_budget.charge(plain_bytes.saturating_mul(32))?;
            Some(
                AhoCorasick::builder()
                    .kind(Some(AhoCorasickKind::NoncontiguousNFA))
                    .build(plain_patterns)
                    .map_err(|_| GeodataError::LimitExceeded("plain matcher"))?,
            )
        };
        let regex = if regex_patterns.is_empty() {
            None
        } else {
            staged_budget.charge(MAX_REGEX_RESERVATION)?;
            Some(
                RegexSetBuilder::new(regex_patterns)
                    .size_limit(MAX_REGEX_PROGRAM_BYTES)
                    .dfa_size_limit(MAX_REGEX_DFA_BYTES)
                    .nest_limit(128)
                    .build()
                    .map_err(|_| GeodataError::InvalidRegex(set_name))?,
            )
        };
        *budget = staged_budget;
        Ok(GeoSiteMatcher(Arc::new(SiteMatcherInner {
            full,
            roots,
            plain,
            regex,
        })))
    }
}

fn decode_domain(
    bytes: &[u8],
    budget: &mut DecodeBudget,
    limits: Limits,
) -> Result<DomainRule, GeodataError> {
    let mut kind = 0_u32;
    let mut pattern = None;
    let mut attributes = BTreeMap::new();
    each_field(bytes, |tag, wire, input| {
        match tag {
            1 => {
                kind = u32::try_from(read_varint(wire, input)?)
                    .map_err(|_| GeodataError::Malformed)?;
            }
            2 => {
                let value = read_bytes(wire, input)?;
                if value.is_empty() || value.len() > limits.pattern_bytes {
                    return Err(GeodataError::LimitExceeded("domain pattern"));
                }
                pattern = Some(text(value)?.to_owned());
            }
            3 => {
                let raw = read_bytes(wire, input)?;
                if raw.len() > MAX_ATTRIBUTE_BYTES {
                    return Err(GeodataError::LimitExceeded("attribute"));
                }
                budget.add(raw.len().saturating_add(96), limits)?;
                let attr = ProtoAttribute::decode(raw).map_err(|_| GeodataError::Malformed)?;
                let key = name(&attr.key).map_err(|_| GeodataError::Malformed)?;
                let value = match attr.value {
                    Some(proto_attribute::Value::Boolean(value)) => AttributeValue::Boolean(value),
                    Some(proto_attribute::Value::Integer(_)) => AttributeValue::Integer,
                    None => return Err(GeodataError::Malformed),
                };
                if attributes.insert(key, value).is_some() {
                    return Err(GeodataError::Malformed);
                }
            }
            _ => skip(wire, tag, input)?,
        }
        Ok(())
    })?;
    if kind > 3 {
        return Err(GeodataError::Malformed);
    }
    Ok(DomainRule {
        kind,
        pattern: pattern.ok_or(GeodataError::Malformed)?,
        attributes,
    })
}

impl GeoSiteMatcher {
    #[must_use]
    pub fn matches(&self, hostname: &str) -> bool {
        let host = hostname
            .strip_suffix('.')
            .unwrap_or(hostname)
            .to_ascii_lowercase();
        if host.is_empty() || host.parse::<IpAddr>().is_ok() || host.starts_with('[') {
            return false;
        }
        if self.0.full.contains(&host) || self.0.roots.contains(&host) {
            return true;
        }
        let mut suffix = host.as_str();
        while let Some((_, rest)) = suffix.split_once('.') {
            if self.0.roots.contains(rest) {
                return true;
            }
            suffix = rest;
        }
        self.0
            .plain
            .as_ref()
            .is_some_and(|matcher| matcher.is_match(&host))
            || self
                .0
                .regex
                .as_ref()
                .is_some_and(|regex| regex.is_match(&host))
    }
}

impl GeoIpDatabase {
    pub fn decode(bytes: &[u8]) -> Result<Self, GeodataError> {
        Self::decode_with_limits(bytes, Limits::default())
    }

    fn decode_with_limits(bytes: &[u8], limits: Limits) -> Result<Self, GeodataError> {
        if bytes.len() > limits.database_bytes {
            return Err(GeodataError::DatabaseTooLarge);
        }
        let mut budget = DecodeBudget::default();
        let mut sets = BTreeMap::new();
        each_field(bytes, |tag, wire, input| {
            if tag != 1 {
                return skip(wire, tag, input);
            }
            if sets.len() >= limits.sets {
                return Err(GeodataError::LimitExceeded("set"));
            }
            let entry = read_bytes(wire, input)?;
            let mut set_name = None;
            let mut inverse = false;
            let mut prefixes = Vec::new();
            each_field(entry, |tag, wire, input| {
                match tag {
                    1 => {
                        set_name = Some(
                            name(text(read_bytes(wire, input)?)?)
                                .map_err(|_| GeodataError::Malformed)?,
                        );
                    }
                    2 => {
                        let raw = read_bytes(wire, input)?;
                        budget.add(raw.len().saturating_add(64), limits)?;
                        prefixes.push(decode_cidr(raw)?);
                    }
                    3 => inverse = read_varint(wire, input)? != 0,
                    _ => skip(wire, tag, input)?,
                }
                Ok(())
            })?;
            let set_name = set_name.ok_or(GeodataError::Malformed)?;
            if sets
                .insert(set_name.clone(), GeoIpSet { inverse, prefixes })
                .is_some()
            {
                return Err(GeodataError::DuplicateSet(set_name));
            }
            Ok(())
        })?;
        Ok(Self { sets })
    }

    pub fn compile(&self, value: &str) -> Result<GeoIpMatcher, GeodataError> {
        self.compile_with_budget(value, &mut CompileBudget::default())
    }

    pub fn compile_with_budget(
        &self,
        value: &str,
        budget: &mut CompileBudget,
    ) -> Result<GeoIpMatcher, GeodataError> {
        let (set_name, attr) = reference(value)?;
        if attr.is_some() {
            return Err(GeodataError::InvalidReference);
        }
        let set = self
            .sets
            .get(&set_name)
            .ok_or_else(|| GeodataError::UnknownSet(set_name.clone()))?;
        let mut staged_budget = budget.clone();
        let mut v4 = HashSet::new();
        let mut v6 = HashSet::new();
        let mut v4_lengths = BTreeSet::new();
        let mut v6_lengths = BTreeSet::new();
        for (addr, prefix) in &set.prefixes {
            staged_budget.charge(80)?;
            match addr {
                IpAddr::V4(ip) => {
                    v4.insert((u32::from(*ip) & v4_mask(*prefix), *prefix));
                    v4_lengths.insert(*prefix);
                }
                IpAddr::V6(ip) => {
                    v6.insert((u128::from(*ip) & v6_mask(*prefix), *prefix));
                    v6_lengths.insert(*prefix);
                }
            }
        }
        *budget = staged_budget;
        Ok(GeoIpMatcher(Arc::new(IpMatcherInner {
            v4,
            v6,
            v4_lengths: v4_lengths.into_iter().collect(),
            v6_lengths: v6_lengths.into_iter().collect(),
            inverse: set.inverse,
        })))
    }
}

fn decode_cidr(bytes: &[u8]) -> Result<(IpAddr, u8), GeodataError> {
    let mut ip = None;
    let mut prefix = 0_u64;
    each_field(bytes, |tag, wire, input| {
        match tag {
            1 => {
                let raw = read_bytes(wire, input)?;
                ip = Some(match raw.len() {
                    4 => {
                        IpAddr::from(<[u8; 4]>::try_from(raw).map_err(|_| GeodataError::Malformed)?)
                    }
                    16 => IpAddr::from(
                        <[u8; 16]>::try_from(raw).map_err(|_| GeodataError::Malformed)?,
                    ),
                    _ => return Err(GeodataError::Malformed),
                });
            }
            2 => prefix = read_varint(wire, input)?,
            _ => skip(wire, tag, input)?,
        }
        Ok(())
    })?;
    let ip = ip.ok_or(GeodataError::Malformed)?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(GeodataError::Malformed);
    }
    Ok((ip, prefix as u8))
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}
fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

impl GeoIpMatcher {
    #[must_use]
    pub fn matches(&self, target: Option<IpAddr>) -> bool {
        let Some(target) = target else {
            return false;
        };
        let member = match target {
            IpAddr::V4(ip) => {
                let value = u32::from(ip);
                self.0
                    .v4_lengths
                    .iter()
                    .any(|prefix| self.0.v4.contains(&(value & v4_mask(*prefix), *prefix)))
            }
            IpAddr::V6(ip) => {
                let value = u128::from(ip);
                self.0
                    .v6_lengths
                    .iter()
                    .any(|prefix| self.0.v6.contains(&(value & v6_mask(*prefix), *prefix)))
            }
        };
        member ^ self.0.inverse
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, PartialEq, Message)]
    struct SiteList {
        #[prost(message, repeated, tag = "1")]
        entry: Vec<Site>,
    }
    #[derive(Clone, PartialEq, Message)]
    struct Site {
        #[prost(string, tag = "1")]
        name: String,
        #[prost(message, repeated, tag = "2")]
        domain: Vec<Domain>,
    }
    #[derive(Clone, PartialEq, Message)]
    struct Domain {
        #[prost(uint32, tag = "1")]
        kind: u32,
        #[prost(string, tag = "2")]
        value: String,
        #[prost(message, repeated, tag = "3")]
        attributes: Vec<ProtoAttribute>,
    }
    #[derive(Clone, PartialEq, Message)]
    struct IpList {
        #[prost(message, repeated, tag = "1")]
        entry: Vec<IpSet>,
    }
    #[derive(Clone, PartialEq, Message)]
    struct IpSet {
        #[prost(string, tag = "1")]
        name: String,
        #[prost(message, repeated, tag = "2")]
        cidr: Vec<Cidr>,
        #[prost(bool, tag = "3")]
        inverse: bool,
    }
    #[derive(Clone, PartialEq, Message)]
    struct Cidr {
        #[prost(bytes, tag = "1")]
        ip: Vec<u8>,
        #[prost(uint32, tag = "2")]
        prefix: u32,
    }

    fn rule(kind: u32, value: &str) -> Domain {
        Domain {
            kind,
            value: value.into(),
            attributes: Vec::new(),
        }
    }
    fn attr(key: &str, value: proto_attribute::Value) -> ProtoAttribute {
        ProtoAttribute {
            key: key.into(),
            value: Some(value),
        }
    }
    fn site(name: &str, domain: Vec<Domain>) -> Site {
        Site {
            name: name.into(),
            domain,
        }
    }
    fn geoip(name: &str, inverse: bool, cidr: Vec<Cidr>) -> IpSet {
        IpSet {
            name: name.into(),
            inverse,
            cidr,
        }
    }
    fn cidr(ip: &str, prefix: u32) -> Cidr {
        let address: IpAddr = ip.parse().unwrap();
        Cidr {
            ip: match address {
                IpAddr::V4(v) => v.octets().to_vec(),
                IpAddr::V6(v) => v.octets().to_vec(),
            },
            prefix,
        }
    }
    fn site_db(sites: Vec<Site>) -> GeoSiteDatabase {
        GeoSiteDatabase::decode(&SiteList { entry: sites }.encode_to_vec()).unwrap()
    }
    fn ip_db(sets: Vec<IpSet>) -> GeoIpDatabase {
        GeoIpDatabase::decode(&IpList { entry: sets }.encode_to_vec()).unwrap()
    }

    #[test]
    fn geosite_matches_upstream_domain_types_and_dns_boundaries() {
        let db = site_db(vec![site(
            "HuggingFace",
            vec![
                rule(2, "hf.co"),
                rule(2, "huggingface.co"),
                rule(3, "exact.example"),
                rule(0, "inside"),
                rule(1, r"^cdn[0-9]+\.example$"),
            ],
        )]);
        let matcher = db.compile("HUGGINGFACE").unwrap();
        for host in [
            "HF.CO",
            "us.aws.cdn.hf.co",
            "huggingface.co.",
            "exact.example",
            "xinsidey.example",
            "CDN7.EXAMPLE",
        ] {
            assert!(matcher.matches(host), "should match {host}");
        }
        for host in [
            "nothf.co",
            "hf.co.evil",
            "x.exact.example",
            "cdnx.example",
            "127.0.0.1",
            "",
        ] {
            assert!(!matcher.matches(host), "must not match {host}");
        }
        // A hostname with more than one trailing root dot is not normalized into a match.
        assert!(!matcher.matches("huggingface.co.."));
    }

    #[test]
    fn geosite_selects_boolean_attributes_and_rejects_unknown_or_integer_attributes() {
        let mut selected = rule(2, "ads.example");
        selected
            .attributes
            .push(attr("AdS", proto_attribute::Value::Boolean(true)));
        let mut excluded = rule(2, "not-ads.example");
        excluded
            .attributes
            .push(attr("ads", proto_attribute::Value::Boolean(false)));
        let mut typed = rule(2, "typed.example");
        typed
            .attributes
            .push(attr("rank", proto_attribute::Value::Integer(7)));
        let db = site_db(vec![site("Example", vec![selected, excluded, typed])]);
        let ads = db.compile("EXAMPLE@ADS").unwrap();
        assert!(ads.matches("a.ads.example"));
        assert!(!ads.matches("not-ads.example"));
        assert!(matches!(
            db.compile("example@missing"),
            Err(GeodataError::UnknownAttribute { .. })
        ));
        assert!(matches!(
            db.compile("example@rank"),
            Err(GeodataError::UnsupportedAttribute { .. })
        ));
        assert!(matches!(
            db.compile("example@ads@extra"),
            Err(GeodataError::InvalidReference)
        ));
    }

    #[test]
    fn regex_is_compiled_only_for_selected_rules_and_fails_closed() {
        let mut invalid = rule(1, "(?=unsupported)");
        invalid
            .attributes
            .push(attr("other", proto_attribute::Value::Boolean(true)));
        let mut valid = rule(2, "good.test");
        valid
            .attributes
            .push(attr("chosen", proto_attribute::Value::Boolean(true)));
        let db = site_db(vec![site("rules", vec![valid, invalid])]);
        assert!(db.compile("rules@chosen").unwrap().matches("good.test"));
        assert!(matches!(
            db.compile("rules"),
            Err(GeodataError::InvalidRegex(_))
        ));
    }

    #[test]
    fn regex_uses_normalized_hostname_with_case_sensitive_pattern_and_inline_flags() {
        let db = site_db(vec![
            site("sensitive", vec![rule(1, r"^CDN\.example$")]),
            site("insensitive", vec![rule(1, r"(?i)^CDN\.example$")]),
        ]);
        assert!(!db.compile("sensitive").unwrap().matches("CDN.example"));
        assert!(db.compile("insensitive").unwrap().matches("CDN.example"));
    }

    #[test]
    fn geoip_checks_prefixes_inverse_unknown_and_address_family() {
        let db = ip_db(vec![
            geoip(
                "normal",
                false,
                vec![cidr("192.0.2.39", 24), cidr("2001:db8:abcd::1", 48)],
            ),
            geoip("inverse", true, vec![cidr("192.0.2.0", 24)]),
        ]);
        let normal = db.compile("NORMAL").unwrap();
        assert!(normal.matches(Some("192.0.2.0".parse().unwrap())));
        assert!(normal.matches(Some("192.0.2.255".parse().unwrap())));
        assert!(!normal.matches(Some("192.0.3.0".parse().unwrap())));
        assert!(normal.matches(Some("2001:db8:abcd:ffff::1".parse().unwrap())));
        assert!(!normal.matches(Some("2001:db8:abce::1".parse().unwrap())));
        assert!(!normal.matches(Some("::ffff:192.0.2.1".parse().unwrap())));
        let inverse = db.compile("inverse").unwrap();
        assert!(!inverse.matches(None));
        assert!(!inverse.matches(Some("192.0.2.99".parse().unwrap())));
        assert!(inverse.matches(Some("192.0.3.1".parse().unwrap())));
        assert!(inverse.matches(Some("::ffff:192.0.2.1".parse().unwrap())));
        assert!(matches!(
            db.compile("normal@ads"),
            Err(GeodataError::InvalidReference)
        ));
    }

    #[test]
    fn invalid_wire_values_and_duplicate_sets_are_rejected() {
        let valid = SiteList {
            entry: vec![site("first", vec![rule(2, "example.org")])],
        }
        .encode_to_vec();
        assert!(matches!(
            GeoSiteDatabase::decode(&valid[..valid.len() - 1]),
            Err(GeodataError::Malformed)
        ));
        assert!(matches!(
            GeoSiteDatabase::decode(&[0x0a, 0xff]),
            Err(GeodataError::Malformed)
        ));
        let duplicate = SiteList {
            entry: vec![site("first", vec![]), site("FIRST", vec![])],
        }
        .encode_to_vec();
        assert!(matches!(
            GeoSiteDatabase::decode(&duplicate),
            Err(GeodataError::DuplicateSet(_))
        ));
        let unknown = SiteList {
            entry: vec![site("first", vec![rule(4, "example.org")])],
        }
        .encode_to_vec();
        assert!(matches!(
            GeoSiteDatabase::decode(&unknown),
            Err(GeodataError::Malformed)
        ));
        for bad in [
            Cidr {
                ip: vec![1, 2, 3],
                prefix: 24,
            },
            cidr("192.0.2.1", 33),
            cidr("2001:db8::1", 129),
        ] {
            let value = IpList {
                entry: vec![geoip("bad", false, vec![bad])],
            }
            .encode_to_vec();
            assert!(matches!(
                GeoIpDatabase::decode(&value),
                Err(GeodataError::Malformed)
            ));
        }
    }

    #[test]
    fn byte_entry_set_pattern_and_compilation_budgets_are_enforced() {
        let bytes = SiteList {
            entry: vec![
                site("a", vec![rule(2, "example.org"), rule(2, "next.example")]),
                site("b", vec![]),
            ],
        }
        .encode_to_vec();
        let limits = Limits {
            database_bytes: bytes.len() - 1,
            ..Limits::default()
        };
        assert!(matches!(
            GeoSiteDatabase::decode_with_limits(&bytes, limits),
            Err(GeodataError::DatabaseTooLarge)
        ));
        let limits = Limits {
            entries: 1,
            ..Limits::default()
        };
        assert!(matches!(
            GeoSiteDatabase::decode_with_limits(&bytes, limits),
            Err(GeodataError::LimitExceeded("entry"))
        ));
        let limits = Limits {
            sets: 1,
            ..Limits::default()
        };
        assert!(matches!(
            GeoSiteDatabase::decode_with_limits(&bytes, limits),
            Err(GeodataError::LimitExceeded("set"))
        ));
        let limits = Limits {
            pattern_bytes: 3,
            ..Limits::default()
        };
        assert!(matches!(
            GeoSiteDatabase::decode_with_limits(&bytes, limits),
            Err(GeodataError::LimitExceeded("domain pattern"))
        ));
        let limits = Limits {
            decoded_bytes: 1,
            ..Limits::default()
        };
        assert!(matches!(
            GeoSiteDatabase::decode_with_limits(&bytes, limits),
            Err(GeodataError::LimitExceeded("decoded memory"))
        ));
        let db = GeoSiteDatabase::decode(&bytes).unwrap();
        let mut budget = CompileBudget { remaining: 1 };
        assert!(matches!(
            db.compile_with_budget("a", &mut budget),
            Err(GeodataError::LimitExceeded("compiled memory"))
        ));
        assert_eq!(
            budget.remaining(),
            1,
            "failed candidates do not consume budget"
        );
    }
}

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, Metadata, ResponseCode};
use hickory_proto::rr::RData;
use pathchord_core::TargetEndpoint as WireTargetEndpoint;
use pathchord_path::{SessionUdpError, SessionUdpHandle};
use pathchord_policy::{DnsBlockedResponse, DnsPolicyConfig, DnsRoute, Endpoint, Selector};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::sync::{Mutex, Semaphore};

pub const MAX_DNS_MESSAGE_BYTES: usize = u16::MAX as usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRouteSelection {
    Local,
    Transit {
        namespace: String,
        proxy_selector: Selector,
        servers: Vec<Endpoint>,
    },
    Egress {
        namespace: String,
        egress_selector: Selector,
        servers: Vec<Endpoint>,
    },
}

impl DnsRouteSelection {
    #[must_use]
    pub const fn route(&self) -> DnsRoute {
        match self {
            Self::Local => DnsRoute::Local,
            Self::Transit { .. } => DnsRoute::Transit,
            Self::Egress { .. } => DnsRoute::Egress,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRouteRequest {
    pub selection: DnsRouteSelection,
    pub wire_query: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum DnsAdapterError {
    #[error("DNS adapter is unavailable")]
    Unavailable,
    #[error("DNS adapter returned a malformed response")]
    Protocol,
    #[error("DNS adapter response exceeds the configured limit")]
    ResponseTooLarge,
}

#[async_trait]
pub trait DnsRouteAdapter: Send + Sync {
    async fn exchange(&self, request: DnsRouteRequest) -> Result<Vec<u8>, DnsAdapterError>;

    fn protected_endpoints(&self) -> BTreeSet<SocketAddr> {
        BTreeSet::new()
    }
}

#[derive(Clone, Default)]
pub struct DnsAdapters {
    local: Option<Arc<dyn DnsRouteAdapter>>,
    transit: Option<Arc<dyn DnsRouteAdapter>>,
    egress: Option<Arc<dyn DnsRouteAdapter>>,
}

impl std::fmt::Debug for DnsAdapters {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DnsAdapters")
            .field("local", &self.local.is_some())
            .field("transit", &self.transit.is_some())
            .field("egress", &self.egress.is_some())
            .finish()
    }
}

impl DnsAdapters {
    #[must_use]
    pub fn with_local(mut self, adapter: Arc<dyn DnsRouteAdapter>) -> Self {
        self.local = Some(adapter);
        self
    }

    #[must_use]
    pub fn with_transit(mut self, adapter: Arc<dyn DnsRouteAdapter>) -> Self {
        self.transit = Some(adapter);
        self
    }

    #[must_use]
    pub fn with_egress(mut self, adapter: Arc<dyn DnsRouteAdapter>) -> Self {
        self.egress = Some(adapter);
        self
    }

    fn adapter(&self, route: DnsRoute) -> Option<Arc<dyn DnsRouteAdapter>> {
        match route {
            DnsRoute::Local => self.local.clone(),
            DnsRoute::Transit => self.transit.clone(),
            DnsRoute::Egress => self.egress.clone(),
            DnsRoute::Blocked => None,
        }
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum DnsError {
    #[error("DNS policy is invalid")]
    InvalidPolicy,
    #[error("DNS query is malformed")]
    MalformedQuery,
    #[error("DNS response is malformed")]
    MalformedResponse,
    #[error("DNS inflight limit is exhausted")]
    InflightLimit,
    #[error("DNS {route:?} route timed out")]
    Timeout { route: DnsRoute },
    #[error("DNS {route:?} route is unavailable")]
    Unavailable { route: DnsRoute },
    #[error("DNS {route:?} route violated the DNS message contract")]
    Protocol { route: DnsRoute },
}

#[derive(Debug)]
pub struct DnsRuntime {
    policy: DnsPolicyConfig,
    adapters: DnsAdapters,
    inflight: Arc<Semaphore>,
    cache: Mutex<DnsCache>,
}

impl DnsRuntime {
    pub fn new(policy: DnsPolicyConfig, adapters: DnsAdapters) -> Result<Self, DnsError> {
        if policy.max_inflight == 0
            || policy.timeout_seconds == 0
            || policy.cache.max_entries > 1_000_000
            || policy.cache.max_ttl_seconds == 0
            || (policy.default_route == DnsRoute::Transit
                && (policy.transit_proxy_selector.is_none() || policy.transit_servers.is_empty()))
            || (policy.default_route == DnsRoute::Egress
                && (policy.egress_selector.is_none() || policy.egress_servers.is_empty()))
        {
            return Err(DnsError::InvalidPolicy);
        }
        let max_inflight =
            usize::try_from(policy.max_inflight).map_err(|_| DnsError::InvalidPolicy)?;
        Ok(Self {
            cache: Mutex::new(DnsCache::new(
                policy.cache.enabled,
                policy.cache.max_entries as usize,
                policy.cache.max_ttl_seconds,
            )),
            policy,
            adapters,
            inflight: Arc::new(Semaphore::new(max_inflight)),
        })
    }

    pub async fn resolve(&self, wire_query: &[u8]) -> Result<Vec<u8>, DnsError> {
        if wire_query.len() > MAX_DNS_MESSAGE_BYTES {
            return Err(DnsError::MalformedQuery);
        }
        let permit = Arc::clone(&self.inflight)
            .try_acquire_owned()
            .map_err(|_| DnsError::InflightLimit)?;
        let query = Message::from_vec(wire_query).map_err(|_| DnsError::MalformedQuery)?;
        if query.metadata.message_type != MessageType::Query || query.queries.is_empty() {
            return Err(DnsError::MalformedQuery);
        }

        if self.policy.default_route == DnsRoute::Blocked {
            drop(permit);
            return blocked_response(&query, self.policy.blocked_response);
        }

        let cache_key = canonical_query_key(&query)?;
        if let Some(response) =
            self.cache
                .lock()
                .await
                .get(&cache_key, query.metadata.id, Instant::now())
        {
            drop(permit);
            return Ok(response);
        }

        let selection = self.selection()?;
        let route = selection.route();
        let adapter = self
            .adapters
            .adapter(route)
            .ok_or(DnsError::Unavailable { route })?;
        let request = DnsRouteRequest {
            selection,
            wire_query: wire_query.to_vec(),
        };
        let response = tokio::time::timeout(
            Duration::from_secs(self.policy.timeout_seconds),
            adapter.exchange(request),
        )
        .await
        .map_err(|_| DnsError::Timeout { route })?
        .map_err(|error| map_adapter_error(route, error))?;
        drop(permit);
        if response.len() > MAX_DNS_MESSAGE_BYTES {
            return Err(DnsError::Protocol { route });
        }
        let message = Message::from_vec(&response).map_err(|_| DnsError::MalformedResponse)?;
        validate_response(&query, &message).map_err(|_| DnsError::Protocol { route })?;
        self.cache
            .lock()
            .await
            .insert(cache_key, message, Instant::now());
        Ok(response)
    }

    #[must_use]
    pub fn protected_endpoints(&self) -> BTreeSet<SocketAddr> {
        let mut endpoints: BTreeSet<_> = [DnsRoute::Local, DnsRoute::Transit, DnsRoute::Egress]
            .into_iter()
            .filter_map(|route| self.adapters.adapter(route))
            .flat_map(|adapter| adapter.protected_endpoints())
            .collect();
        endpoints.extend(
            self.policy
                .transit_servers
                .iter()
                .chain(&self.policy.egress_servers)
                .filter_map(endpoint_socket_addr),
        );
        endpoints
    }

    fn selection(&self) -> Result<DnsRouteSelection, DnsError> {
        match self.policy.default_route {
            DnsRoute::Local => Ok(DnsRouteSelection::Local),
            DnsRoute::Transit => self
                .policy
                .transit_proxy_selector
                .clone()
                .map(|proxy_selector| DnsRouteSelection::Transit {
                    namespace: self.policy.id.namespace().to_owned(),
                    proxy_selector,
                    servers: self.policy.transit_servers.clone(),
                })
                .ok_or(DnsError::InvalidPolicy),
            DnsRoute::Egress => self
                .policy
                .egress_selector
                .clone()
                .map(|egress_selector| DnsRouteSelection::Egress {
                    namespace: self.policy.id.namespace().to_owned(),
                    egress_selector,
                    servers: self.policy.egress_servers.clone(),
                })
                .ok_or(DnsError::InvalidPolicy),
            DnsRoute::Blocked => Err(DnsError::InvalidPolicy),
        }
    }
}

fn map_adapter_error(route: DnsRoute, error: DnsAdapterError) -> DnsError {
    match error {
        DnsAdapterError::Unavailable => DnsError::Unavailable { route },
        DnsAdapterError::Protocol | DnsAdapterError::ResponseTooLarge => {
            DnsError::Protocol { route }
        }
    }
}

fn blocked_response(query: &Message, blocked: DnsBlockedResponse) -> Result<Vec<u8>, DnsError> {
    let mut response = Message::response(query.metadata.id, query.metadata.op_code);
    response.metadata = Metadata::response_from_request(&query.metadata);
    response.metadata.response_code = match blocked {
        DnsBlockedResponse::Nxdomain => ResponseCode::NXDomain,
        DnsBlockedResponse::Refused => ResponseCode::Refused,
        DnsBlockedResponse::Servfail => ResponseCode::ServFail,
    };
    response.add_queries(query.queries.iter().cloned());
    response.to_vec().map_err(|_| DnsError::MalformedResponse)
}

fn canonical_query_key(query: &Message) -> Result<Vec<u8>, DnsError> {
    let mut canonical = query.clone();
    canonical.metadata.id = 0;
    canonical.to_vec().map_err(|_| DnsError::MalformedQuery)
}

fn validate_response(query: &Message, response: &Message) -> Result<(), ()> {
    if response.metadata.message_type != MessageType::Response
        || response.metadata.id != query.metadata.id
        || response.metadata.op_code != query.metadata.op_code
        || response.queries != query.queries
    {
        Err(())
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct CacheEntry {
    message: Message,
    inserted_at: Instant,
    expires_at: Instant,
}

#[derive(Debug)]
struct DnsCache {
    enabled: bool,
    max_entries: usize,
    max_ttl_seconds: u32,
    entries: BTreeMap<Vec<u8>, CacheEntry>,
    insertion_order: VecDeque<Vec<u8>>,
}

impl DnsCache {
    fn new(enabled: bool, max_entries: usize, max_ttl_seconds: u32) -> Self {
        Self {
            enabled,
            max_entries,
            max_ttl_seconds,
            entries: BTreeMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    fn get(&mut self, key: &[u8], id: u16, now: Instant) -> Option<Vec<u8>> {
        if !self.enabled {
            return None;
        }
        let expired = self
            .entries
            .get(key)
            .is_some_and(|entry| now >= entry.expires_at);
        if expired {
            self.remove(key);
            return None;
        }
        let entry = self.entries.get(key)?;
        let elapsed = u32::try_from(now.saturating_duration_since(entry.inserted_at).as_secs())
            .unwrap_or(u32::MAX);
        let mut message = entry.message.clone();
        message.metadata.id = id;
        decrement_ttls(&mut message, elapsed);
        message.to_vec().ok()
    }

    fn insert(&mut self, key: Vec<u8>, mut message: Message, now: Instant) {
        if !self.enabled
            || self.max_entries == 0
            || message.signature.is_some()
            || !matches!(
                message.metadata.response_code,
                ResponseCode::NoError | ResponseCode::NXDomain
            )
        {
            return;
        }
        cap_ttls(&mut message, self.max_ttl_seconds);
        let Some(ttl) = cache_ttl(&message).filter(|ttl| *ttl > 0) else {
            return;
        };
        message.metadata.id = 0;
        self.remove(&key);
        while self.entries.len() >= self.max_entries {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        self.insertion_order.push_back(key.clone());
        self.entries.insert(
            key,
            CacheEntry {
                message,
                inserted_at: now,
                expires_at: now + Duration::from_secs(u64::from(ttl)),
            },
        );
    }

    fn remove(&mut self, key: &[u8]) {
        self.entries.remove(key);
        self.insertion_order.retain(|candidate| candidate != key);
    }
}

fn cache_ttl(message: &Message) -> Option<u32> {
    if !message.answers.is_empty() {
        return message.answers.iter().map(|record| record.ttl).min();
    }
    if !matches!(
        message.metadata.response_code,
        ResponseCode::NoError | ResponseCode::NXDomain
    ) {
        return None;
    }
    message
        .authorities
        .iter()
        .filter_map(|record| match &record.data {
            RData::SOA(soa) => Some(record.ttl.min(soa.minimum)),
            _ => None,
        })
        .min()
}

fn cap_ttls(message: &mut Message, maximum: u32) {
    for record in message
        .answers
        .iter_mut()
        .chain(message.authorities.iter_mut())
        .chain(message.additionals.iter_mut())
    {
        record.ttl = record.ttl.min(maximum);
    }
}

fn decrement_ttls(message: &mut Message, elapsed: u32) {
    for record in message
        .answers
        .iter_mut()
        .chain(message.authorities.iter_mut())
        .chain(message.additionals.iter_mut())
    {
        record.ttl = record.ttl.saturating_sub(elapsed);
    }
}

#[derive(Debug)]
pub struct LocalDnsAdapter {
    servers: Vec<Endpoint>,
    protected: RwLock<BTreeSet<SocketAddr>>,
}

impl LocalDnsAdapter {
    pub fn new(servers: Vec<Endpoint>) -> Result<Self, DnsAdapterError> {
        if servers.is_empty()
            || servers
                .iter()
                .any(|server| server.host.is_empty() || server.port == 0)
        {
            return Err(DnsAdapterError::Unavailable);
        }
        let protected = servers.iter().filter_map(endpoint_socket_addr).collect();
        Ok(Self {
            servers,
            protected: RwLock::new(protected),
        })
    }

    async fn addresses(&self, server: &Endpoint) -> Result<Vec<SocketAddr>, DnsAdapterError> {
        let addresses: Vec<_> = lookup_host((server.host.as_str(), server.port))
            .await
            .map_err(|_| DnsAdapterError::Unavailable)?
            .collect();
        if addresses.is_empty() {
            return Err(DnsAdapterError::Unavailable);
        }
        self.protected
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(addresses.iter().copied());
        Ok(addresses)
    }

    async fn exchange_address(
        &self,
        address: SocketAddr,
        query: &[u8],
    ) -> Result<Vec<u8>, DnsAdapterError> {
        let bind = match address.ip() {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|_| DnsAdapterError::Unavailable)?;
        socket
            .connect(address)
            .await
            .map_err(|_| DnsAdapterError::Unavailable)?;
        socket
            .send(query)
            .await
            .map_err(|_| DnsAdapterError::Unavailable)?;
        let mut response = vec![0_u8; MAX_DNS_MESSAGE_BYTES];
        let received = socket
            .recv(&mut response)
            .await
            .map_err(|_| DnsAdapterError::Unavailable)?;
        response.truncate(received);
        let message = Message::from_vec(&response).map_err(|_| DnsAdapterError::Protocol)?;
        if message.metadata.truncation {
            tcp_dns_exchange(address, query).await
        } else {
            Ok(response)
        }
    }
}

#[async_trait]
impl DnsRouteAdapter for LocalDnsAdapter {
    async fn exchange(&self, request: DnsRouteRequest) -> Result<Vec<u8>, DnsAdapterError> {
        let mut last_error = DnsAdapterError::Unavailable;
        for server in &self.servers {
            let addresses = match self.addresses(server).await {
                Ok(addresses) => addresses,
                Err(error) => {
                    last_error = error;
                    continue;
                }
            };
            for address in addresses {
                match self.exchange_address(address, &request.wire_query).await {
                    Ok(response) => return Ok(response),
                    Err(error) => last_error = error,
                }
            }
        }
        Err(last_error)
    }

    fn protected_endpoints(&self) -> BTreeSet<SocketAddr> {
        self.protected
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

async fn tcp_dns_exchange(address: SocketAddr, query: &[u8]) -> Result<Vec<u8>, DnsAdapterError> {
    let length = u16::try_from(query.len()).map_err(|_| DnsAdapterError::ResponseTooLarge)?;
    let mut stream = TcpStream::connect(address)
        .await
        .map_err(|_| DnsAdapterError::Unavailable)?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|_| DnsAdapterError::Unavailable)?;
    stream
        .write_all(query)
        .await
        .map_err(|_| DnsAdapterError::Unavailable)?;
    let response_length = stream
        .read_u16()
        .await
        .map_err(|_| DnsAdapterError::Protocol)?;
    let mut response = vec![0_u8; usize::from(response_length)];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|_| DnsAdapterError::Protocol)?;
    Message::from_vec(&response).map_err(|_| DnsAdapterError::Protocol)?;
    Ok(response)
}

fn endpoint_socket_addr(endpoint: &Endpoint) -> Option<SocketAddr> {
    endpoint
        .host
        .parse::<IpAddr>()
        .ok()
        .map(|address| SocketAddr::new(address, endpoint.port))
}

pub struct SessionUdpDnsAdapter {
    session: Arc<dyn SessionUdpHandle>,
}

impl std::fmt::Debug for SessionUdpDnsAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionUdpDnsAdapter")
            .finish_non_exhaustive()
    }
}

impl SessionUdpDnsAdapter {
    #[must_use]
    pub fn new(session: Arc<dyn SessionUdpHandle>) -> Self {
        Self { session }
    }
}

#[async_trait]
impl DnsRouteAdapter for SessionUdpDnsAdapter {
    async fn exchange(&self, request: DnsRouteRequest) -> Result<Vec<u8>, DnsAdapterError> {
        let endpoint = match &request.selection {
            DnsRouteSelection::Transit { servers, .. }
            | DnsRouteSelection::Egress { servers, .. } => servers.first(),
            DnsRouteSelection::Local => None,
        }
        .ok_or(DnsAdapterError::Unavailable)?;
        let target = WireTargetEndpoint {
            hostname: endpoint.host.as_bytes().to_vec(),
            port: endpoint.port,
            resolved_addresses: endpoint.host.parse::<IpAddr>().ok().into_iter().collect(),
        };
        let target = if target.resolved_addresses.is_empty() {
            target
        } else {
            WireTargetEndpoint {
                hostname: Vec::new(),
                ..target
            }
        };
        self.session
            .exchange_datagram(target, request.wire_query, MAX_DNS_MESSAGE_BYTES)
            .await
            .map_err(|error| match error {
                SessionUdpError::ResponseTooLarge => DnsAdapterError::ResponseTooLarge,
                SessionUdpError::Unavailable | SessionUdpError::Exchange => {
                    DnsAdapterError::Unavailable
                }
            })
    }

    fn protected_endpoints(&self) -> BTreeSet<SocketAddr> {
        BTreeSet::new()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hickory_proto::op::Query;
    use hickory_proto::rr::rdata::{A, AAAA, SOA};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use pathchord_policy::{DnsCacheConfig, DnsLocalConfig, DnsPolicyConfig, DnsPolicyId};
    use tokio::net::TcpListener;
    use tokio::sync::Notify;

    use super::*;

    fn selector() -> Selector {
        Selector {
            tags: BTreeSet::from(["dns".into()]),
            ..Selector::default()
        }
    }

    fn policy(route: DnsRoute) -> DnsPolicyConfig {
        DnsPolicyConfig {
            id: DnsPolicyId::new("default-dns"),
            default_route: route,
            local: Some(DnsLocalConfig {
                servers: vec![Endpoint {
                    host: "127.0.0.1".into(),
                    port: 53,
                }],
            }),
            transit_proxy_selector: (route == DnsRoute::Transit).then(selector),
            transit_servers: (route == DnsRoute::Transit)
                .then(|| Endpoint {
                    host: "192.0.2.53".into(),
                    port: 53,
                })
                .into_iter()
                .collect(),
            egress_selector: (route == DnsRoute::Egress).then(selector),
            egress_servers: (route == DnsRoute::Egress)
                .then(|| Endpoint {
                    host: "192.0.2.53".into(),
                    port: 53,
                })
                .into_iter()
                .collect(),
            blocked_response: DnsBlockedResponse::Refused,
            timeout_seconds: 1,
            max_inflight: 4,
            cache: DnsCacheConfig {
                enabled: true,
                max_entries: 16,
                max_ttl_seconds: 300,
            },
        }
    }

    fn query(id: u16, record_type: RecordType) -> Vec<u8> {
        let mut message = Message::query();
        message.metadata.id = id;
        message.add_query(Query::query(
            Name::from_ascii("www.example.test.").unwrap(),
            record_type,
        ));
        message.to_vec().unwrap()
    }

    fn answer(query: &[u8], ttl: u32) -> Vec<u8> {
        let query = Message::from_vec(query).unwrap();
        let mut response = Message::response(query.metadata.id, query.metadata.op_code);
        response.metadata = Metadata::response_from_request(&query.metadata);
        response.metadata.recursion_available = true;
        response.add_queries(query.queries.iter().cloned());
        let name = query.queries[0].name().clone();
        let data = match query.queries[0].query_type() {
            RecordType::AAAA => RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
            _ => RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        };
        response.add_answer(Record::from_rdata(name, ttl, data));
        response.to_vec().unwrap()
    }

    fn negative_answer(query: &[u8], ttl: u32, minimum: u32) -> Vec<u8> {
        let query = Message::from_vec(query).unwrap();
        let mut response = Message::response(query.metadata.id, query.metadata.op_code);
        response.metadata = Metadata::response_from_request(&query.metadata);
        response.metadata.response_code = ResponseCode::NXDomain;
        response.add_queries(query.queries.iter().cloned());
        response.authorities.push(Record::from_rdata(
            Name::from_ascii("example.test.").unwrap(),
            ttl,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.example.test.").unwrap(),
                Name::from_ascii("hostmaster.example.test.").unwrap(),
                1,
                60,
                60,
                60,
                minimum,
            )),
        ));
        response.to_vec().unwrap()
    }

    #[derive(Debug)]
    struct AnswerAdapter {
        calls: AtomicUsize,
        ttl: u32,
    }

    impl AnswerAdapter {
        fn new(ttl: u32) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                ttl,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl DnsRouteAdapter for AnswerAdapter {
        async fn exchange(&self, request: DnsRouteRequest) -> Result<Vec<u8>, DnsAdapterError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(answer(&request.wire_query, self.ttl))
        }
    }

    #[derive(Debug)]
    struct NegativeAdapter {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl DnsRouteAdapter for NegativeAdapter {
        async fn exchange(&self, request: DnsRouteRequest) -> Result<Vec<u8>, DnsAdapterError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(negative_answer(&request.wire_query, 60, 30))
        }
    }

    #[derive(Debug)]
    struct FailingAdapter {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl DnsRouteAdapter for FailingAdapter {
        async fn exchange(&self, _request: DnsRouteRequest) -> Result<Vec<u8>, DnsAdapterError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err(DnsAdapterError::Unavailable)
        }
    }

    #[tokio::test]
    async fn selects_each_configured_route_without_cross_route_fallback() {
        for route in [DnsRoute::Local, DnsRoute::Transit, DnsRoute::Egress] {
            let local = Arc::new(AnswerAdapter::new(60));
            let transit = Arc::new(AnswerAdapter::new(60));
            let egress = Arc::new(AnswerAdapter::new(60));
            let runtime = DnsRuntime::new(
                policy(route),
                DnsAdapters::default()
                    .with_local(local.clone())
                    .with_transit(transit.clone())
                    .with_egress(egress.clone()),
            )
            .unwrap();
            let response = runtime.resolve(&query(7, RecordType::A)).await.unwrap();
            assert_eq!(Message::from_vec(&response).unwrap().answers.len(), 1);
            assert_eq!(local.calls(), usize::from(route == DnsRoute::Local));
            assert_eq!(transit.calls(), usize::from(route == DnsRoute::Transit));
            assert_eq!(egress.calls(), usize::from(route == DnsRoute::Egress));
        }

        let local = Arc::new(AnswerAdapter::new(60));
        let transit = Arc::new(FailingAdapter {
            calls: AtomicUsize::new(0),
        });
        let runtime = DnsRuntime::new(
            policy(DnsRoute::Transit),
            DnsAdapters::default()
                .with_local(local.clone())
                .with_transit(transit.clone()),
        )
        .unwrap();
        assert_eq!(
            runtime.resolve(&query(8, RecordType::A)).await,
            Err(DnsError::Unavailable {
                route: DnsRoute::Transit
            })
        );
        assert_eq!(transit.calls.load(Ordering::Relaxed), 1);
        assert_eq!(local.calls(), 0);
    }

    #[tokio::test]
    async fn blocked_route_returns_configured_error_without_fake_addresses() {
        for (blocked, expected) in [
            (DnsBlockedResponse::Nxdomain, ResponseCode::NXDomain),
            (DnsBlockedResponse::Refused, ResponseCode::Refused),
            (DnsBlockedResponse::Servfail, ResponseCode::ServFail),
        ] {
            let mut config = policy(DnsRoute::Blocked);
            config.blocked_response = blocked;
            let runtime = DnsRuntime::new(config, DnsAdapters::default()).unwrap();
            let response =
                Message::from_vec(&runtime.resolve(&query(9, RecordType::AAAA)).await.unwrap())
                    .unwrap();
            assert_eq!(response.metadata.response_code, expected);
            assert!(response.answers.is_empty());
        }
    }

    #[test]
    fn routed_dns_selection_retains_the_policy_namespace() {
        for route in [DnsRoute::Transit, DnsRoute::Egress] {
            let mut config = policy(route);
            config.id = pathchord_policy::DnsPolicyId::in_namespace("tenant-a", "dns");
            let runtime = DnsRuntime::new(config, DnsAdapters::default()).unwrap();
            match runtime.selection().unwrap() {
                DnsRouteSelection::Transit { namespace, .. }
                | DnsRouteSelection::Egress { namespace, .. } => assert_eq!(namespace, "tenant-a"),
                DnsRouteSelection::Local => panic!("expected a routed DNS selection"),
            }
        }
    }

    #[tokio::test]
    async fn positive_and_negative_ttl_cache_preserve_query_ids() {
        let positive = Arc::new(AnswerAdapter::new(120));
        let runtime = DnsRuntime::new(
            policy(DnsRoute::Transit),
            DnsAdapters::default().with_transit(positive.clone()),
        )
        .unwrap();
        runtime.resolve(&query(10, RecordType::A)).await.unwrap();
        let cached =
            Message::from_vec(&runtime.resolve(&query(11, RecordType::A)).await.unwrap()).unwrap();
        assert_eq!(cached.metadata.id, 11);
        assert_eq!(positive.calls(), 1);

        let negative = Arc::new(NegativeAdapter {
            calls: AtomicUsize::new(0),
        });
        let runtime = DnsRuntime::new(
            policy(DnsRoute::Egress),
            DnsAdapters::default().with_egress(negative.clone()),
        )
        .unwrap();
        runtime.resolve(&query(12, RecordType::AAAA)).await.unwrap();
        let cached =
            Message::from_vec(&runtime.resolve(&query(13, RecordType::AAAA)).await.unwrap())
                .unwrap();
        assert_eq!(cached.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(cached.metadata.id, 13);
        assert_eq!(negative.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn cache_expiry_and_ttl_decrement_are_bounded() {
        let wire = query(14, RecordType::A);
        let query_message = Message::from_vec(&wire).unwrap();
        let key = canonical_query_key(&query_message).unwrap();
        let message = Message::from_vec(&answer(&wire, 120)).unwrap();
        let now = Instant::now();
        let mut cache = DnsCache::new(true, 1, 60);
        cache.insert(key.clone(), message, now);
        let cached =
            Message::from_vec(&cache.get(&key, 15, now + Duration::from_secs(10)).unwrap())
                .unwrap();
        assert_eq!(cached.answers[0].ttl, 50);
        let second_wire = query(16, RecordType::AAAA);
        let second_query = Message::from_vec(&second_wire).unwrap();
        let second_key = canonical_query_key(&second_query).unwrap();
        cache.insert(
            second_key.clone(),
            Message::from_vec(&answer(&second_wire, 30)).unwrap(),
            now + Duration::from_secs(11),
        );
        assert!(cache.get(&key, 17, now + Duration::from_secs(11)).is_none());
        assert!(
            cache
                .get(&second_key, 18, now + Duration::from_secs(12))
                .is_some()
        );
        assert!(
            cache
                .get(&second_key, 19, now + Duration::from_secs(42))
                .is_none()
        );
    }

    #[derive(Debug)]
    struct PendingAdapter;

    #[async_trait]
    impl DnsRouteAdapter for PendingAdapter {
        async fn exchange(&self, _request: DnsRouteRequest) -> Result<Vec<u8>, DnsAdapterError> {
            std::future::pending().await
        }
    }

    #[tokio::test(start_paused = true)]
    async fn route_timeout_is_typed() {
        let runtime = Arc::new(
            DnsRuntime::new(
                policy(DnsRoute::Transit),
                DnsAdapters::default().with_transit(Arc::new(PendingAdapter)),
            )
            .unwrap(),
        );
        let task = tokio::spawn({
            let runtime = Arc::clone(&runtime);
            async move { runtime.resolve(&query(17, RecordType::A)).await }
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(
            task.await.unwrap(),
            Err(DnsError::Timeout {
                route: DnsRoute::Transit
            })
        );
    }

    #[derive(Debug)]
    struct GatedAdapter {
        entered: Notify,
        release: Notify,
    }

    #[async_trait]
    impl DnsRouteAdapter for GatedAdapter {
        async fn exchange(&self, request: DnsRouteRequest) -> Result<Vec<u8>, DnsAdapterError> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(answer(&request.wire_query, 60))
        }
    }

    #[tokio::test]
    async fn inflight_limit_rejects_untracked_waiters() {
        let adapter = Arc::new(GatedAdapter {
            entered: Notify::new(),
            release: Notify::new(),
        });
        let mut config = policy(DnsRoute::Transit);
        config.max_inflight = 1;
        let runtime = Arc::new(
            DnsRuntime::new(config, DnsAdapters::default().with_transit(adapter.clone())).unwrap(),
        );
        let first = tokio::spawn({
            let runtime = Arc::clone(&runtime);
            async move { runtime.resolve(&query(18, RecordType::A)).await }
        });
        adapter.entered.notified().await;
        assert_eq!(
            runtime.resolve(&query(19, RecordType::A)).await,
            Err(DnsError::InflightLimit)
        );
        adapter.release.notify_one();
        first.await.unwrap().unwrap();
    }

    #[derive(Debug)]
    struct FakeSessionUdp {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl SessionUdpHandle for FakeSessionUdp {
        async fn exchange_datagram(
            &self,
            _target: WireTargetEndpoint,
            request: Vec<u8>,
            maximum_response: usize,
        ) -> Result<Vec<u8>, SessionUdpError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let response = answer(&request, 60);
            if response.len() > maximum_response {
                Err(SessionUdpError::ResponseTooLarge)
            } else {
                Ok(response)
            }
        }
    }

    #[tokio::test]
    async fn egress_adapter_uses_the_session_udp_handle() {
        let session = Arc::new(FakeSessionUdp {
            calls: AtomicUsize::new(0),
        });
        let adapter = Arc::new(SessionUdpDnsAdapter::new(session.clone()));
        let runtime = DnsRuntime::new(
            policy(DnsRoute::Egress),
            DnsAdapters::default().with_egress(adapter),
        )
        .unwrap();
        runtime.resolve(&query(20, RecordType::AAAA)).await.unwrap();
        assert_eq!(session.calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            runtime.protected_endpoints(),
            BTreeSet::from(["192.0.2.53:53".parse().unwrap()])
        );
    }

    #[test]
    fn local_adapter_protects_ipv4_and_ipv6_upstreams() {
        let adapter = LocalDnsAdapter::new(vec![
            Endpoint {
                host: "192.0.2.53".into(),
                port: 53,
            },
            Endpoint {
                host: "2001:db8::53".into(),
                port: 53,
            },
        ])
        .unwrap();
        assert_eq!(
            adapter.protected_endpoints(),
            BTreeSet::from([
                "192.0.2.53:53".parse().unwrap(),
                "[2001:db8::53]:53".parse().unwrap(),
            ])
        );
    }

    #[tokio::test]
    async fn local_udp_queries_an_ipv6_upstream() {
        let Ok(socket) = UdpSocket::bind("[::1]:0").await else {
            return;
        };
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buffer = vec![0_u8; MAX_DNS_MESSAGE_BYTES];
            let (received, peer) = socket.recv_from(&mut buffer).await.unwrap();
            buffer.truncate(received);
            socket.send_to(&answer(&buffer, 60), peer).await.unwrap();
        });
        let adapter = Arc::new(
            LocalDnsAdapter::new(vec![Endpoint {
                host: address.ip().to_string(),
                port: address.port(),
            }])
            .unwrap(),
        );
        let mut config = policy(DnsRoute::Local);
        config.local = Some(DnsLocalConfig {
            servers: vec![Endpoint {
                host: address.ip().to_string(),
                port: address.port(),
            }],
        });
        let runtime = DnsRuntime::new(config, DnsAdapters::default().with_local(adapter)).unwrap();
        let response =
            Message::from_vec(&runtime.resolve(&query(22, RecordType::AAAA)).await.unwrap())
                .unwrap();
        assert!(matches!(response.answers[0].data, RData::AAAA(_)));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn local_udp_truncation_retries_over_tcp() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(address).await.unwrap();
        let udp_task = tokio::spawn(async move {
            let mut buffer = vec![0_u8; MAX_DNS_MESSAGE_BYTES];
            let (received, peer) = udp.recv_from(&mut buffer).await.unwrap();
            buffer.truncate(received);
            let query = Message::from_vec(&buffer).unwrap();
            let mut truncated = Message::response(query.metadata.id, query.metadata.op_code);
            truncated.metadata = Metadata::response_from_request(&query.metadata);
            truncated.metadata.truncation = true;
            truncated.add_queries(query.queries.iter().cloned());
            udp.send_to(&truncated.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let tcp_task = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let length = stream.read_u16().await.unwrap();
            let mut request = vec![0_u8; usize::from(length)];
            stream.read_exact(&mut request).await.unwrap();
            let response = answer(&request, 60);
            stream
                .write_all(&(response.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&response).await.unwrap();
        });
        let adapter = Arc::new(
            LocalDnsAdapter::new(vec![Endpoint {
                host: address.ip().to_string(),
                port: address.port(),
            }])
            .unwrap(),
        );
        let mut config = policy(DnsRoute::Local);
        config.local = Some(DnsLocalConfig {
            servers: vec![Endpoint {
                host: address.ip().to_string(),
                port: address.port(),
            }],
        });
        let runtime = DnsRuntime::new(config, DnsAdapters::default().with_local(adapter)).unwrap();
        let response =
            Message::from_vec(&runtime.resolve(&query(21, RecordType::A)).await.unwrap()).unwrap();
        assert!(!response.metadata.truncation);
        assert_eq!(response.answers.len(), 1);
        udp_task.await.unwrap();
        tcp_task.await.unwrap();
    }
}

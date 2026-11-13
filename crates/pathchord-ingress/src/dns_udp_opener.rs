//! DNS-policy-aware UDP opener shared by SOCKS, TPROXY, and TUN.

use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::op::{Message, Metadata, ResponseCode};
use tokio::sync::mpsc;

use crate::{
    BoxedUdpFlowHandle, ConnectionContext, DnsError, DnsRuntime, UdpFlowError, UdpFlowHandle,
    UdpFlowOpener,
};

#[derive(Clone)]
pub struct DnsAwareUdpFlowOpener {
    dns: Arc<DnsRuntime>,
    delegate: Arc<dyn UdpFlowOpener>,
}

impl std::fmt::Debug for DnsAwareUdpFlowOpener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DnsAwareUdpFlowOpener(..)")
    }
}

impl DnsAwareUdpFlowOpener {
    #[must_use]
    pub fn new(dns: Arc<DnsRuntime>, delegate: Arc<dyn UdpFlowOpener>) -> Self {
        Self { dns, delegate }
    }
}

#[async_trait]
impl UdpFlowOpener for DnsAwareUdpFlowOpener {
    async fn open_udp(
        &self,
        context: &ConnectionContext,
    ) -> Result<BoxedUdpFlowHandle, UdpFlowError> {
        if context.target.port != 53 {
            return self.delegate.open_udp(context).await;
        }
        let (responses_tx, responses) = mpsc::channel(8);
        Ok(Box::new(DnsUdpHandle {
            dns: Arc::clone(&self.dns),
            responses_tx,
            responses,
        }))
    }
}

#[derive(Debug)]
struct DnsUdpHandle {
    dns: Arc<DnsRuntime>,
    responses_tx: mpsc::Sender<Vec<u8>>,
    responses: mpsc::Receiver<Vec<u8>>,
}

#[async_trait]
impl UdpFlowHandle for DnsUdpHandle {
    async fn send(&mut self, payload: Vec<u8>) -> Result<(), UdpFlowError> {
        let response = match self.dns.resolve(&payload).await {
            Ok(response) => response,
            Err(DnsError::MalformedQuery) => {
                return Err(UdpFlowError::Task("DNS query is malformed".to_owned()));
            }
            Err(error) => servfail_response(&payload).map_err(|_| {
                UdpFlowError::Task(format!("DNS failure could not be encoded: {error}"))
            })?,
        };
        self.responses_tx
            .send(response)
            .await
            .map_err(|_| UdpFlowError::Task("DNS response queue is closed".to_owned()))
    }

    async fn receive(&mut self) -> Option<Vec<u8>> {
        self.responses.recv().await
    }

    async fn close(self: Box<Self>) -> Result<(), UdpFlowError> {
        Ok(())
    }
}

fn servfail_response(query: &[u8]) -> Result<Vec<u8>, ()> {
    let query = Message::from_vec(query).map_err(|_| ())?;
    let mut response = Message::response(query.metadata.id, query.metadata.op_code);
    response.metadata = Metadata::response_from_request(&query.metadata);
    response.metadata.response_code = ResponseCode::ServFail;
    response.add_queries(query.queries.iter().cloned());
    response.to_vec().map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use pathchord_policy::{
        DnsBlockedResponse, DnsCacheConfig, DnsPolicyConfig, DnsPolicyId, DnsRoute,
    };

    use crate::{DnsAdapters, DnsRouteAdapter, DnsRouteRequest};

    #[derive(Debug)]
    struct RejectDelegate;

    #[async_trait]
    impl UdpFlowOpener for RejectDelegate {
        async fn open_udp(
            &self,
            _context: &ConnectionContext,
        ) -> Result<BoxedUdpFlowHandle, UdpFlowError> {
            Err(UdpFlowError::Open(
                "delegate must not be used for DNS".to_owned(),
            ))
        }
    }

    #[derive(Debug)]
    struct LocalAnswer;

    #[async_trait]
    impl DnsRouteAdapter for LocalAnswer {
        async fn exchange(
            &self,
            request: DnsRouteRequest,
        ) -> Result<Vec<u8>, crate::DnsAdapterError> {
            let query = Message::from_vec(&request.wire_query).unwrap();
            let mut response = Message::response(query.metadata.id, query.metadata.op_code);
            response.metadata = Metadata::response_from_request(&query.metadata);
            response.add_queries(query.queries.iter().cloned());
            response.add_answer(Record::from_rdata(
                query.queries[0].name.clone(),
                60,
                RData::A(A("192.0.2.10".parse().unwrap())),
            ));
            Ok(response.to_vec().unwrap())
        }
    }

    fn policy(route: DnsRoute, blocked_response: DnsBlockedResponse) -> DnsPolicyConfig {
        DnsPolicyConfig {
            id: DnsPolicyId::new("dns"),
            default_route: route,
            local: None,
            transit_proxy_selector: None,
            egress_selector: None,
            blocked_response,
            timeout_seconds: 1,
            max_inflight: 8,
            cache: DnsCacheConfig {
                enabled: false,
                max_entries: 16,
                max_ttl_seconds: 300,
            },
            transit_servers: Vec::new(),
            egress_servers: Vec::new(),
        }
    }

    fn query() -> Vec<u8> {
        let mut query = Message::new(7, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii("example.test.").unwrap(),
            RecordType::A,
        ));
        query.to_vec().unwrap()
    }

    fn context(port: u16) -> ConnectionContext {
        ConnectionContext {
            flow_tags: std::collections::BTreeSet::new(),
            listener_id: crate::ListenerId::new("udp"),
            source: "127.0.0.1:12345".parse().unwrap(),
            authentication_identity: None,
            process: None,
            protocol: crate::FlowProtocol::Udp,
            target: crate::TargetAddress {
                host: crate::TargetHost::Ip("192.0.2.53".parse().unwrap()),
                port,
            },
        }
    }

    #[tokio::test]
    async fn blocked_dns_returns_policy_response_without_delegate_fallback() {
        let dns = Arc::new(
            DnsRuntime::new(
                policy(DnsRoute::Blocked, DnsBlockedResponse::Refused),
                DnsAdapters::default(),
            )
            .unwrap(),
        );
        let opener = DnsAwareUdpFlowOpener::new(dns, Arc::new(RejectDelegate));
        let mut handle = opener.open_udp(&context(53)).await.unwrap();
        handle.send(query()).await.unwrap();
        let response = Message::from_vec(&handle.receive().await.unwrap()).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::Refused);
        assert_eq!(response.metadata.id, 7);
    }

    #[tokio::test]
    async fn local_dns_response_is_consumed_by_the_udp_opener() {
        let dns = Arc::new(
            DnsRuntime::new(
                policy(DnsRoute::Local, DnsBlockedResponse::Servfail),
                DnsAdapters::default().with_local(Arc::new(LocalAnswer)),
            )
            .unwrap(),
        );
        let opener = DnsAwareUdpFlowOpener::new(dns, Arc::new(RejectDelegate));
        let mut handle = opener.open_udp(&context(53)).await.unwrap();
        handle.send(query()).await.unwrap();
        let response = Message::from_vec(&handle.receive().await.unwrap()).unwrap();
        assert_eq!(response.answers.len(), 1);
        assert_eq!(
            response.answers[0].data,
            RData::A("192.0.2.10".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn unavailable_dns_becomes_servfail_and_non_dns_delegates() {
        let dns = Arc::new(
            DnsRuntime::new(
                policy(DnsRoute::Local, DnsBlockedResponse::Servfail),
                DnsAdapters::default(),
            )
            .unwrap(),
        );
        let opener = DnsAwareUdpFlowOpener::new(dns, Arc::new(RejectDelegate));
        let mut handle = opener.open_udp(&context(53)).await.unwrap();
        handle.send(query()).await.unwrap();
        let response = Message::from_vec(&handle.receive().await.unwrap()).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(matches!(
            opener.open_udp(&context(54)).await,
            Err(UdpFlowError::Open(_))
        ));
    }
}

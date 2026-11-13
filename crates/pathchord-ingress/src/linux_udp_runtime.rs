//! Supervised Linux TPROXY UDP-to-Session association runtime.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::{
    BoxedUdpFlowHandle, ConnectionContext, FlowProtocol, ListenerId, ProcessMetadataProvider,
    ProcessSocketTuple, TargetAddress, TargetHost, TransparentDatagram, TransparentUdpAdapter,
    UdpFlowOpener,
};

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum TransparentUdpRuntimeError {
    #[error("transparent UDP adapter failed: {0}")]
    Adapter(String),
    #[error("transparent UDP association task failed: {0}")]
    Task(String),
    #[error("transparent UDP association capacity must be greater than zero")]
    InvalidCapacity,
}

#[derive(Debug, Clone)]
pub struct TransparentUdpRuntimeConfig {
    pub listener_id: ListenerId,
    pub flow_tags: std::collections::BTreeSet<String>,
    pub process_metadata: pathchord_policy::ProcessMetadataRequest,
    pub process_metadata_provider: Arc<dyn ProcessMetadataProvider>,
    pub max_associations: usize,
    pub association_queue: usize,
    pub idle_timeout: Duration,
}

impl TransparentUdpRuntimeConfig {
    fn validate(&self) -> Result<(), TransparentUdpRuntimeError> {
        if self.max_associations == 0 || self.association_queue == 0 {
            Err(TransparentUdpRuntimeError::InvalidCapacity)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransparentUdpRuntimeReport {
    pub received_datagrams: u64,
    pub sent_datagrams: u64,
    pub rejected_datagrams: u64,
    pub expired_associations: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AssociationKey {
    source: std::net::SocketAddr,
    target: std::net::SocketAddr,
}

pub async fn run_transparent_udp<A, O, F>(
    adapter: Arc<A>,
    opener: Arc<O>,
    config: TransparentUdpRuntimeConfig,
    shutdown: F,
) -> Result<TransparentUdpRuntimeReport, TransparentUdpRuntimeError>
where
    A: TransparentUdpAdapter + ?Sized + 'static,
    O: UdpFlowOpener + ?Sized + 'static,
    F: Future<Output = ()> + Send,
{
    config.validate()?;
    let mut associations = BTreeMap::<AssociationKey, mpsc::Sender<Vec<u8>>>::new();
    let mut tasks = JoinSet::<Result<AssociationKey, TransparentUdpRuntimeError>>::new();
    let mut report = TransparentUdpRuntimeReport::default();
    let sent_datagrams = Arc::new(AtomicU64::new(0));
    let mut shutdown = Box::pin(shutdown);

    loop {
        tokio::select! {
            () = shutdown.as_mut() => break,
            joined = tasks.join_next(), if !tasks.is_empty() => {
                match joined {
                    Some(Ok(Ok(key))) => {
                        associations.remove(&key);
                        report.expired_associations = report.expired_associations.saturating_add(1);
                    }
                    Some(Ok(Err(error))) => return Err(error),
                    Some(Err(error)) => return Err(TransparentUdpRuntimeError::Task(error.to_string())),
                    None => {}
                }
            }
            received = adapter.receive() => {
                let datagram = received.map_err(|error| {
                    TransparentUdpRuntimeError::Adapter(error.to_string())
                })?;
                report.received_datagrams = report.received_datagrams.saturating_add(1);
                let key = AssociationKey {
                    source: datagram.source,
                    target: datagram.target,
                };
                if let Some(sender) = associations.get(&key) {
                    if sender.try_send(datagram.payload).is_err() {
                        report.rejected_datagrams = report.rejected_datagrams.saturating_add(1);
                    }
                    continue;
                }
                if associations.len() >= config.max_associations {
                    report.rejected_datagrams = report.rejected_datagrams.saturating_add(1);
                    continue;
                }
                let context = ConnectionContext {
                    flow_tags: config.flow_tags.clone(),
                    listener_id: config.listener_id.clone(),
                    source: datagram.source,
                    authentication_identity: None,
                    process: None,
                    protocol: FlowProtocol::Udp,
                    target: TargetAddress {
                        host: TargetHost::Ip(datagram.target.ip()),
                        port: datagram.target.port(),
                    },
                };
                let mut context = context;
                if !config.process_metadata.is_empty() {
                    context.process = config
                        .process_metadata_provider
                        .lookup(
                            ProcessSocketTuple {
                                source: datagram.source,
                                local: datagram.target,
                            },
                            config.process_metadata,
                        )
                        .await;
                }
                let handle = match opener.open_udp(&context).await {
                    Ok(handle) => handle,
                    Err(_) => {
                        report.rejected_datagrams = report.rejected_datagrams.saturating_add(1);
                        continue;
                    }
                };
                let (requests, request_rx) = mpsc::channel(config.association_queue);
                requests.try_send(datagram.payload).map_err(|_| {
                    TransparentUdpRuntimeError::Task("new UDP association queue is closed".to_owned())
                })?;
                associations.insert(key.clone(), requests);
                tasks.spawn(run_association(
                    key,
                    handle,
                    request_rx,
                    Arc::clone(&adapter),
                    Arc::clone(&sent_datagrams),
                    config.idle_timeout,
                ));
            }
        }
    }

    associations.clear();
    let graceful = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(1), graceful)
        .await
        .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    report.sent_datagrams = sent_datagrams.load(Ordering::Relaxed);
    Ok(report)
}

async fn run_association<A>(
    key: AssociationKey,
    mut handle: BoxedUdpFlowHandle,
    mut requests: mpsc::Receiver<Vec<u8>>,
    adapter: Arc<A>,
    sent_datagrams: Arc<AtomicU64>,
    idle_timeout: Duration,
) -> Result<AssociationKey, TransparentUdpRuntimeError>
where
    A: TransparentUdpAdapter + ?Sized + 'static,
{
    loop {
        let idle = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle);
        tokio::select! {
            () = &mut idle => {
                handle.close().await.map_err(|error| TransparentUdpRuntimeError::Task(error.to_string()))?;
                return Ok(key);
            }
            request = requests.recv() => {
                let Some(request) = request else {
                    handle.close().await.map_err(|error| TransparentUdpRuntimeError::Task(error.to_string()))?;
                    return Ok(key);
                };
                handle.send(request).await.map_err(|error| TransparentUdpRuntimeError::Task(error.to_string()))?;
            }
            response = handle.receive() => {
                let Some(payload) = response else {
                    return Ok(key);
                };
                adapter.send(&TransparentDatagram {
                    source: key.source,
                    target: key.target,
                    payload,
                }).await.map_err(|error| {
                    TransparentUdpRuntimeError::Adapter(error.to_string())
                })?;
                sent_datagrams.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UdpFlowHandle;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use tokio::sync::oneshot;

    #[derive(Debug, Default)]
    struct FakeOpener {
        contexts: Mutex<Vec<ConnectionContext>>,
    }

    #[derive(Debug)]
    struct EchoHandle {
        responses: mpsc::Receiver<Vec<u8>>,
        response_tx: mpsc::Sender<Vec<u8>>,
    }

    #[async_trait]
    impl UdpFlowHandle for EchoHandle {
        async fn send(&mut self, mut payload: Vec<u8>) -> Result<(), crate::UdpFlowError> {
            payload.reverse();
            self.response_tx
                .send(payload)
                .await
                .map_err(|_| crate::UdpFlowError::Task("response closed".to_owned()))
        }

        async fn receive(&mut self) -> Option<Vec<u8>> {
            self.responses.recv().await
        }

        async fn close(self: Box<Self>) -> Result<(), crate::UdpFlowError> {
            Ok(())
        }
    }

    #[async_trait]
    impl UdpFlowOpener for FakeOpener {
        async fn open_udp(
            &self,
            context: &ConnectionContext,
        ) -> Result<BoxedUdpFlowHandle, crate::UdpFlowError> {
            self.contexts.lock().unwrap().push(context.clone());
            let (response_tx, responses) = mpsc::channel(4);
            Ok(Box::new(EchoHandle {
                responses,
                response_tx,
            }))
        }
    }

    #[tokio::test]
    async fn maps_transparent_datagrams_to_one_udp_association() {
        let adapter = crate::FakeTransparentUdpAdapter::new(4);
        let opener = Arc::new(FakeOpener::default());
        let (shutdown, signal) = oneshot::channel();
        let runtime = tokio::spawn(run_transparent_udp(
            Arc::clone(&adapter),
            Arc::clone(&opener),
            TransparentUdpRuntimeConfig {
                listener_id: ListenerId::new("tproxy-udp"),
                flow_tags: std::collections::BTreeSet::from(["dns".to_owned()]),
                process_metadata: pathchord_policy::ProcessMetadataRequest::default(),
                process_metadata_provider: Arc::new(crate::NoopProcessMetadataProvider),
                max_associations: 4,
                association_queue: 4,
                idle_timeout: Duration::from_secs(60),
            },
            async move {
                let _ = signal.await;
            },
        ));
        let datagram = TransparentDatagram {
            source: "192.0.2.10:12345".parse().unwrap(),
            target: "198.51.100.20:53".parse().unwrap(),
            payload: vec![1, 2, 3],
        };
        adapter.inject(datagram.clone()).await.unwrap();
        for _ in 0..100 {
            if !adapter.sent().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(adapter.sent()[0].payload, vec![3, 2, 1]);
        {
            let contexts = opener.contexts.lock().unwrap();
            assert_eq!(contexts.len(), 1);
            assert!(contexts[0].flow_tags.contains("dns"));
            assert_eq!(contexts[0].source, datagram.source);
            assert_eq!(contexts[0].protocol, FlowProtocol::Udp);
        }
        shutdown.send(()).unwrap();
        runtime.await.unwrap().unwrap();
    }
}

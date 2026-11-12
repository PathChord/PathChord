//! Bounded supervision for local Ingress listeners.
//!
//! A listener owns protocol admission and returns one typed connection at a
//! time. This module owns the process-level lifecycle around those adapters:
//! it bounds accepted flows, bridges them through an injected target dialer,
//! classifies protocol rejections as per-connection failures, and converges
//! every task on shutdown.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{Notify, Semaphore, mpsc};
use tokio::task::JoinSet;

use crate::{
    FlowBridgeError, FlowBridgeStats, HttpConnectListener, IngressListener, IngressTargetDialer,
    ListenerDescriptor, ListenerError, ListenerId, ListenerKind, Socks5Listener, bridge_connection,
};

/// Runtime defaults are deliberately conservative; callers can raise the
/// limit after accounting for target and file-descriptor capacity.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerRuntimeConfig {
    pub max_connections: usize,
}

impl Default for ListenerRuntimeConfig {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }
}

impl ListenerRuntimeConfig {
    fn validate(self) -> Result<Self, RuntimeError> {
        if self.max_connections == 0 {
            return Err(RuntimeError::InvalidMaxConnections);
        }
        Ok(self)
    }
}

/// Runtime lifecycle and flow events. Payloads contain listener metadata and
/// counters only; target payloads and credentials are never emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerRuntimeEvent {
    ListenerStarted {
        listener_id: ListenerId,
        bind: std::net::SocketAddr,
    },
    ProtocolRejected {
        listener_id: ListenerId,
        reason: String,
    },
    ConnectionAccepted {
        listener_id: ListenerId,
    },
    ConnectionCompleted {
        listener_id: ListenerId,
        stats: FlowBridgeStats,
    },
    ConnectionFailed {
        listener_id: ListenerId,
        error: String,
    },
    ListenerFailed {
        listener_id: ListenerId,
        error: String,
    },
    ListenerStopped {
        listener_id: ListenerId,
    },
}

pub type ListenerRuntimeEventSender = mpsc::UnboundedSender<ListenerRuntimeEvent>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeReport {
    pub listener_count: usize,
    pub accepted_connections: u64,
    pub protocol_rejections: u64,
    pub completed_connections: u64,
    pub failed_connections: u64,
    pub local_to_target_bytes: u64,
    pub target_to_local_bytes: u64,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    #[error("listener runtime has no configured listeners")]
    NoListeners,
    #[error("max_connections must be greater than zero")]
    InvalidMaxConnections,
    #[error("duplicate listener id: {0}")]
    DuplicateListener(String),
    #[error("listener {listener_id:?} of kind {kind:?} is not supported by this runtime")]
    UnsupportedListener {
        listener_id: ListenerId,
        kind: ListenerKind,
    },
    #[error("listener {listener_id:?} address lookup failed: {source}")]
    ListenerAddress {
        listener_id: ListenerId,
        source: ListenerError,
    },
    #[error("listener {listener_id:?} failed: {source}")]
    Listener {
        listener_id: ListenerId,
        source: ListenerError,
    },
    #[error("listener task failed: {0}")]
    Task(String),
}

/// Owns configured listener adapters and supervises their flow tasks.
pub struct ListenerRuntime<D> {
    dialer: Arc<D>,
    config: ListenerRuntimeConfig,
    listeners: Vec<Arc<dyn IngressListener>>,
    listener_ids: std::collections::BTreeSet<ListenerId>,
    events: Option<ListenerRuntimeEventSender>,
}

impl<D> std::fmt::Debug for ListenerRuntime<D> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ListenerRuntime")
            .field("config", &self.config)
            .field("listener_count", &self.listeners.len())
            .finish_non_exhaustive()
    }
}

impl<D> ListenerRuntime<D>
where
    D: IngressTargetDialer + 'static,
{
    #[must_use]
    pub fn new(dialer: D) -> Self {
        Self {
            dialer: Arc::new(dialer),
            config: ListenerRuntimeConfig::default(),
            listeners: Vec::new(),
            listener_ids: std::collections::BTreeSet::new(),
            events: None,
        }
    }

    pub fn with_config(dialer: D, config: ListenerRuntimeConfig) -> Result<Self, RuntimeError> {
        Ok(Self {
            dialer: Arc::new(dialer),
            config: config.validate()?,
            listeners: Vec::new(),
            listener_ids: std::collections::BTreeSet::new(),
            events: None,
        })
    }

    /// Binds the supported TCP listener kinds from declarative descriptors.
    /// TPROXY, REDIRECT, and TUN require platform-specific adapters and are
    /// rejected explicitly instead of silently becoming ordinary TCP sockets.
    pub async fn bind_descriptors<I>(
        dialer: D,
        config: ListenerRuntimeConfig,
        descriptors: I,
    ) -> Result<Self, RuntimeError>
    where
        I: IntoIterator<Item = ListenerDescriptor>,
    {
        let mut runtime = Self::with_config(dialer, config)?;
        for descriptor in descriptors {
            if runtime.listener_ids.contains(&descriptor.id) {
                return Err(RuntimeError::DuplicateListener(
                    descriptor.id.as_str().to_owned(),
                ));
            }
            let listener: Arc<dyn IngressListener> = match descriptor.kind {
                ListenerKind::Http => Arc::new(
                    HttpConnectListener::bind(descriptor.clone())
                        .await
                        .map_err(|source| RuntimeError::Listener {
                            listener_id: descriptor.id.clone(),
                            source,
                        })?,
                ),
                ListenerKind::Socks5 => Arc::new(
                    Socks5Listener::bind(descriptor.clone())
                        .await
                        .map_err(|source| RuntimeError::Listener {
                            listener_id: descriptor.id.clone(),
                            source,
                        })?,
                ),
                kind => {
                    return Err(RuntimeError::UnsupportedListener {
                        listener_id: descriptor.id,
                        kind,
                    });
                }
            };
            runtime.add_listener_arc(listener)?;
        }
        Ok(runtime)
    }

    #[must_use]
    pub fn config(&self) -> ListenerRuntimeConfig {
        self.config
    }

    pub fn set_event_sender(&mut self, sender: ListenerRuntimeEventSender) {
        self.events = Some(sender);
    }

    #[must_use]
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    pub fn add_listener<L>(&mut self, listener: L) -> Result<(), RuntimeError>
    where
        L: IngressListener + 'static,
    {
        self.add_listener_arc(Arc::new(listener))
    }

    pub fn add_listener_arc(
        &mut self,
        listener: Arc<dyn IngressListener>,
    ) -> Result<(), RuntimeError> {
        let id = listener.descriptor().id.clone();
        if !self.listener_ids.insert(id.clone()) {
            return Err(RuntimeError::DuplicateListener(id.as_str().to_owned()));
        }
        self.listeners.push(listener);
        Ok(())
    }

    /// Returns actual platform addresses, including an ephemeral port assigned
    /// by the operating system. This is safe to publish through control-plane
    /// inventory because it contains no credentials or connection state.
    pub fn listener_addresses(
        &self,
    ) -> Result<BTreeMap<ListenerId, std::net::SocketAddr>, RuntimeError> {
        self.listeners
            .iter()
            .map(|listener| {
                listener
                    .local_addr()
                    .map(|address| (listener.descriptor().id.clone(), address))
                    .map_err(|source| RuntimeError::ListenerAddress {
                        listener_id: listener.descriptor().id.clone(),
                        source,
                    })
            })
            .collect()
    }

    /// Runs until one listener fails or `shutdown` resolves. All listener and
    /// bridge tasks are joined before this method returns.
    pub async fn run_until_shutdown<F>(self, shutdown: F) -> Result<RuntimeReport, RuntimeError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if self.listeners.is_empty() {
            return Err(RuntimeError::NoListeners);
        }

        let listener_count = self.listeners.len();
        let semaphore = Arc::new(Semaphore::new(self.config.max_connections));
        let cancellation = Arc::new(RuntimeCancellation::default());
        let counters = Arc::new(RuntimeCounters::default());
        let mut supervisors = JoinSet::new();

        let mut listeners = Vec::with_capacity(self.listeners.len());
        for listener in self.listeners {
            let listener_id = listener.descriptor().id.clone();
            let bind = listener
                .local_addr()
                .map_err(|source| RuntimeError::ListenerAddress {
                    listener_id: listener_id.clone(),
                    source,
                })?;
            listeners.push((listener, listener_id, bind));
        }

        for (listener, listener_id, bind) in listeners {
            emit(
                &self.events,
                ListenerRuntimeEvent::ListenerStarted { listener_id, bind },
            );
            supervisors.spawn(run_listener(
                listener,
                Arc::clone(&self.dialer),
                Arc::clone(&semaphore),
                Arc::clone(&cancellation),
                Arc::clone(&counters),
                self.events.clone(),
            ));
        }

        let mut shutdown = Box::pin(shutdown);
        loop {
            tokio::select! {
                () = shutdown.as_mut() => {
                    cancellation.cancel();
                    join_supervisors(&mut supervisors).await?;
                    return Ok(counters.report(listener_count));
                }
                joined = supervisors.join_next() => {
                    match joined {
                        Some(Ok(Ok(()))) => {
                            if supervisors.is_empty() {
                                cancellation.cancel();
                                return Err(RuntimeError::Task("all listener tasks stopped unexpectedly".to_owned()));
                            }
                        }
                        Some(Ok(Err(error))) => {
                            cancellation.cancel();
                            supervisors.abort_all();
                            let _ = join_supervisors(&mut supervisors).await;
                            return Err(error);
                        }
                        Some(Err(error)) => {
                            cancellation.cancel();
                            supervisors.abort_all();
                            let _ = join_supervisors(&mut supervisors).await;
                            return Err(RuntimeError::Task(error.to_string()));
                        }
                        None => {
                            cancellation.cancel();
                            return Err(RuntimeError::Task("all listener tasks stopped unexpectedly".to_owned()));
                        }
                    }
                }
            }
        }
    }

    pub async fn run(self) -> Result<RuntimeReport, RuntimeError> {
        self.run_until_shutdown(std::future::pending()).await
    }
}

#[derive(Debug, Default)]
struct RuntimeCancellation {
    cancelled: std::sync::atomic::AtomicBool,
    notify: Notify,
}

impl RuntimeCancellation {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    async fn cancelled(&self) {
        loop {
            if self.cancelled.load(Ordering::Acquire) {
                return;
            }
            let notified = self.notify.notified();
            if self.cancelled.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Debug, Default)]
struct RuntimeCounters {
    accepted_connections: AtomicU64,
    protocol_rejections: AtomicU64,
    completed_connections: AtomicU64,
    failed_connections: AtomicU64,
    local_to_target_bytes: AtomicU64,
    target_to_local_bytes: AtomicU64,
}

impl RuntimeCounters {
    fn report(&self, listener_count: usize) -> RuntimeReport {
        RuntimeReport {
            listener_count,
            accepted_connections: self.accepted_connections.load(Ordering::Relaxed),
            protocol_rejections: self.protocol_rejections.load(Ordering::Relaxed),
            completed_connections: self.completed_connections.load(Ordering::Relaxed),
            failed_connections: self.failed_connections.load(Ordering::Relaxed),
            local_to_target_bytes: self.local_to_target_bytes.load(Ordering::Relaxed),
            target_to_local_bytes: self.target_to_local_bytes.load(Ordering::Relaxed),
        }
    }
}

async fn run_listener<D>(
    listener: Arc<dyn IngressListener>,
    dialer: Arc<D>,
    semaphore: Arc<Semaphore>,
    cancellation: Arc<RuntimeCancellation>,
    counters: Arc<RuntimeCounters>,
    events: Option<ListenerRuntimeEventSender>,
) -> Result<(), RuntimeError>
where
    D: IngressTargetDialer + 'static,
{
    let listener_id = listener.descriptor().id.clone();
    let mut flows = JoinSet::new();

    loop {
        drain_completed_flows(&mut flows, &counters, &events, &listener_id).await;

        let permit = tokio::select! {
            () = cancellation.cancelled() => break,
            result = Arc::clone(&semaphore).acquire_owned() => result
                .map_err(|error| RuntimeError::Task(error.to_string()))?,
        };

        let accepted = tokio::select! {
            () = cancellation.cancelled() => {
                drop(permit);
                break;
            }
            result = listener.accept() => result,
        };

        match accepted {
            Ok(connection) => {
                counters
                    .accepted_connections
                    .fetch_add(1, Ordering::Relaxed);
                emit(
                    &events,
                    ListenerRuntimeEvent::ConnectionAccepted {
                        listener_id: listener_id.clone(),
                    },
                );
                let flow_listener_id = listener_id.clone();
                let flow_dialer = Arc::clone(&dialer);
                let flow_counters = Arc::clone(&counters);
                let flow_events = events.clone();
                flows.spawn(async move {
                    let result = bridge_connection(connection, flow_dialer.as_ref()).await;
                    match &result {
                        Ok(stats) => {
                            flow_counters
                                .completed_connections
                                .fetch_add(1, Ordering::Relaxed);
                            flow_counters
                                .local_to_target_bytes
                                .fetch_add(stats.local_to_target_bytes, Ordering::Relaxed);
                            flow_counters
                                .target_to_local_bytes
                                .fetch_add(stats.target_to_local_bytes, Ordering::Relaxed);
                            emit(
                                &flow_events,
                                ListenerRuntimeEvent::ConnectionCompleted {
                                    listener_id: flow_listener_id.clone(),
                                    stats: *stats,
                                },
                            );
                        }
                        Err(error) => {
                            flow_counters
                                .failed_connections
                                .fetch_add(1, Ordering::Relaxed);
                            emit(
                                &flow_events,
                                ListenerRuntimeEvent::ConnectionFailed {
                                    listener_id: flow_listener_id.clone(),
                                    error: error.to_string(),
                                },
                            );
                        }
                    }
                    drop(permit);
                    result
                });
            }
            Err(ListenerError::Protocol(reason)) => {
                drop(permit);
                counters.protocol_rejections.fetch_add(1, Ordering::Relaxed);
                emit(
                    &events,
                    ListenerRuntimeEvent::ProtocolRejected {
                        listener_id: listener_id.clone(),
                        reason,
                    },
                );
            }
            Err(error) => {
                drop(permit);
                emit(
                    &events,
                    ListenerRuntimeEvent::ListenerFailed {
                        listener_id: listener_id.clone(),
                        error: error.to_string(),
                    },
                );
                cancellation.cancel();
                flows.abort_all();
                while flows.join_next().await.is_some() {}
                return Err(RuntimeError::Listener {
                    listener_id,
                    source: error,
                });
            }
        }
    }

    flows.abort_all();
    while flows.join_next().await.is_some() {}
    emit(
        &events,
        ListenerRuntimeEvent::ListenerStopped { listener_id },
    );
    Ok(())
}

async fn drain_completed_flows(
    flows: &mut JoinSet<Result<FlowBridgeStats, FlowBridgeError>>,
    counters: &RuntimeCounters,
    events: &Option<ListenerRuntimeEventSender>,
    listener_id: &ListenerId,
) {
    while let Some(result) = flows.try_join_next() {
        if let Err(error) = result {
            counters.failed_connections.fetch_add(1, Ordering::Relaxed);
            emit(
                events,
                ListenerRuntimeEvent::ConnectionFailed {
                    listener_id: listener_id.clone(),
                    error: error.to_string(),
                },
            );
        }
    }
}

async fn join_supervisors(
    supervisors: &mut JoinSet<Result<(), RuntimeError>>,
) -> Result<(), RuntimeError> {
    let mut first_error = None;
    while let Some(result) = supervisors.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(RuntimeError::Task(error.to_string()));
                }
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn emit(events: &Option<ListenerRuntimeEventSender>, event: ListenerRuntimeEvent) {
    if let Some(sender) = events {
        let _ = sender.send(event);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
    use tokio::sync::oneshot;

    use super::*;
    use crate::{
        AcceptedConnection, ConnectionContext, FixedTargetDialer, FlowProtocol, TargetAddress,
        TargetHost,
    };

    struct ScriptedListener {
        descriptor: ListenerDescriptor,
        queue: Mutex<VecDeque<Result<AcceptedConnection, ListenerError>>>,
        notify: Notify,
    }

    impl ScriptedListener {
        fn new(
            id: &str,
            queue: impl IntoIterator<Item = Result<AcceptedConnection, ListenerError>>,
        ) -> Self {
            Self {
                descriptor: ListenerDescriptor {
                    id: ListenerId::new(id),
                    kind: ListenerKind::Http,
                    bind: "127.0.0.1:0".parse().expect("bind"),
                    authentication_required: false,
                },
                queue: Mutex::new(queue.into_iter().collect()),
                notify: Notify::new(),
            }
        }
    }

    #[async_trait]
    impl IngressListener for ScriptedListener {
        fn descriptor(&self) -> &ListenerDescriptor {
            &self.descriptor
        }

        async fn accept(&self) -> Result<AcceptedConnection, ListenerError> {
            loop {
                if let Some(result) = self.queue.lock().expect("queue lock").pop_front() {
                    return result;
                }
                self.notify.notified().await;
            }
        }
    }

    fn accepted(local: DuplexStream) -> AcceptedConnection {
        AcceptedConnection {
            io: Box::new(local),
            context: ConnectionContext {
                listener_id: ListenerId::new("test"),
                source: "127.0.0.1:1234".parse().expect("source"),
                authentication_identity: None,
                process: None,
                protocol: FlowProtocol::Tcp,
                target: TargetAddress {
                    host: TargetHost::Hostname("example.test".to_owned()),
                    port: 443,
                },
            },
        }
    }

    fn dialer_for(
        target_stream: Arc<Mutex<Option<DuplexStream>>>,
    ) -> FixedTargetDialer<impl FnMut(TargetAddress) -> Result<DuplexStream, FlowBridgeError> + Send>
    {
        FixedTargetDialer::new(move |_| {
            target_stream
                .lock()
                .expect("target lock")
                .take()
                .ok_or_else(|| FlowBridgeError::Dial("target already used".to_owned()))
        })
    }

    #[tokio::test]
    async fn rejects_zero_connection_limit() {
        assert_eq!(
            ListenerRuntime::with_config(
                FixedTargetDialer::new(|_| {
                    Err::<DuplexStream, _>(FlowBridgeError::Dial("unused".to_owned()))
                }),
                ListenerRuntimeConfig { max_connections: 0 },
            )
            .expect_err("zero limit must fail"),
            RuntimeError::InvalidMaxConnections
        );
    }

    #[tokio::test]
    async fn binds_supported_descriptors_and_reports_assigned_addresses() {
        let descriptors = [
            ListenerDescriptor {
                id: ListenerId::new("http"),
                kind: ListenerKind::Http,
                bind: "127.0.0.1:0".parse().expect("HTTP bind"),
                authentication_required: false,
            },
            ListenerDescriptor {
                id: ListenerId::new("socks"),
                kind: ListenerKind::Socks5,
                bind: "127.0.0.1:0".parse().expect("SOCKS bind"),
                authentication_required: false,
            },
        ];
        let runtime = ListenerRuntime::bind_descriptors(
            FixedTargetDialer::new(|_| {
                Err::<DuplexStream, _>(FlowBridgeError::Dial("unused".to_owned()))
            }),
            ListenerRuntimeConfig::default(),
            descriptors,
        )
        .await
        .expect("bind listeners");
        let addresses = runtime.listener_addresses().expect("listener addresses");
        assert_eq!(addresses.len(), 2);
        assert!(addresses.values().all(|address| address.port() != 0));
    }

    #[tokio::test]
    async fn rejects_unsupported_descriptor_kinds_before_starting() {
        let result = ListenerRuntime::bind_descriptors(
            FixedTargetDialer::new(|_| {
                Err::<DuplexStream, _>(FlowBridgeError::Dial("unused".to_owned()))
            }),
            ListenerRuntimeConfig::default(),
            [ListenerDescriptor {
                id: ListenerId::new("tun"),
                kind: ListenerKind::Tun,
                bind: "127.0.0.1:15000".parse().expect("TUN bind"),
                authentication_required: false,
            }],
        )
        .await;
        assert!(matches!(
            result,
            Err(RuntimeError::UnsupportedListener {
                kind: ListenerKind::Tun,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn rejects_duplicate_descriptor_ids_before_binding_the_second_socket() {
        let descriptor = ListenerDescriptor {
            id: ListenerId::new("duplicate"),
            kind: ListenerKind::Http,
            bind: "127.0.0.1:0".parse().expect("HTTP bind"),
            authentication_required: false,
        };
        let result = ListenerRuntime::bind_descriptors(
            FixedTargetDialer::new(|_| {
                Err::<DuplexStream, _>(FlowBridgeError::Dial("unused".to_owned()))
            }),
            ListenerRuntimeConfig::default(),
            [descriptor.clone(), descriptor],
        )
        .await;
        assert!(matches!(
            result,
            Err(RuntimeError::DuplicateListener(id)) if id == "duplicate"
        ));
    }

    #[tokio::test]
    async fn protocol_rejection_is_per_connection_and_shutdown_joins() {
        let listener = ScriptedListener::new(
            "http",
            [Err(ListenerError::Protocol("bad request".to_owned()))],
        );
        let (events, mut receiver) = mpsc::unbounded_channel();
        let mut runtime = ListenerRuntime::new(FixedTargetDialer::new(|_| {
            Err::<DuplexStream, _>(FlowBridgeError::Dial("unused".to_owned()))
        }));
        runtime.set_event_sender(events);
        runtime.add_listener(listener).expect("listener");
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(async move {
            runtime
                .run_until_shutdown(async move {
                    let _ = signal.await;
                })
                .await
        });
        let mut saw_rejection = false;
        while let Some(event) = receiver.recv().await {
            if matches!(event, ListenerRuntimeEvent::ProtocolRejected { .. }) {
                saw_rejection = true;
                break;
            }
        }
        assert!(saw_rejection);
        shutdown.send(()).expect("shutdown receiver");
        let report = task.await.expect("runtime task").expect("runtime result");
        assert_eq!(report.protocol_rejections, 1);
    }

    #[tokio::test]
    async fn fatal_accept_error_stops_runtime() {
        let listener = ScriptedListener::new(
            "broken",
            [Err(ListenerError::Accept("fd closed".to_owned()))],
        );
        let mut runtime = ListenerRuntime::new(FixedTargetDialer::new(|_| {
            Err::<DuplexStream, _>(FlowBridgeError::Dial("unused".to_owned()))
        }));
        runtime.add_listener(listener).expect("listener");
        let result = runtime.run().await;
        assert!(matches!(
            result,
            Err(RuntimeError::Listener {
                source: ListenerError::Accept(_),
                ..
            })
        ));
    }

    #[tokio::test]
    async fn active_flow_is_aborted_on_shutdown() {
        let (local_peer, local_stream) = duplex(128);
        let (target_peer, target_stream) = duplex(128);
        let target_slot = Arc::new(Mutex::new(Some(target_stream)));
        let listener = ScriptedListener::new("http", [Ok(accepted(local_stream))]);
        let mut runtime = ListenerRuntime::new(dialer_for(Arc::clone(&target_slot)));
        runtime.add_listener(listener).expect("listener");
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(async move {
            runtime
                .run_until_shutdown(async move {
                    let _ = signal.await;
                })
                .await
        });
        drop(local_peer);
        drop(target_peer);
        shutdown.send(()).expect("shutdown receiver");
        let report = task.await.expect("runtime task").expect("runtime result");
        assert_eq!(report.listener_count, 1);
    }

    #[tokio::test]
    async fn bridges_accepted_flow_and_reports_stats() {
        let (mut local_peer, local_stream) = duplex(128);
        let (mut target_peer, target_stream) = duplex(128);
        let target_slot = Arc::new(Mutex::new(Some(target_stream)));
        let listener = ScriptedListener::new("http", [Ok(accepted(local_stream))]);
        let (events, mut receiver) = mpsc::unbounded_channel();
        let mut runtime = ListenerRuntime::new(dialer_for(Arc::clone(&target_slot)));
        runtime.set_event_sender(events);
        runtime.add_listener(listener).expect("listener");
        let (shutdown, signal) = oneshot::channel();
        let task = tokio::spawn(async move {
            runtime
                .run_until_shutdown(async move {
                    let _ = signal.await;
                })
                .await
        });
        local_peer.write_all(b"hello").await.expect("write local");
        let mut received = [0_u8; 5];
        target_peer
            .read_exact(&mut received)
            .await
            .expect("read target");
        assert_eq!(&received, b"hello");
        local_peer.shutdown().await.expect("shutdown local");
        target_peer.shutdown().await.expect("shutdown target");
        loop {
            match receiver.recv().await {
                Some(ListenerRuntimeEvent::ConnectionCompleted { stats, .. }) => {
                    assert_eq!(stats.local_to_target_bytes, 5);
                    break;
                }
                Some(_) => {}
                None => panic!("runtime event channel closed before completion"),
            }
        }
        shutdown.send(()).expect("shutdown receiver");
        let report = task.await.expect("runtime task").expect("runtime result");
        assert_eq!(report.accepted_connections, 1);
        assert_eq!(report.completed_connections, 1);
        assert_eq!(report.local_to_target_bytes, 5);
    }
}

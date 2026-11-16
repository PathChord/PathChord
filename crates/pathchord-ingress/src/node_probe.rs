//! Explicit, bounded TCP connection probes for Transit nodes.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pathchord_policy::TransitProxyId;
use pathchord_transit::{AdmissionRevocation, ConnectRequest, Endpoint, TransitAdapter};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitProbeConfig {
    pub target: Endpoint,
    pub timeout: Duration,
    pub max_concurrency: usize,
    pub window_size: usize,
    pub max_nodes_per_batch: usize,
}

impl TransitProbeConfig {
    #[must_use]
    pub fn new(target: Endpoint) -> Self {
        Self {
            target,
            timeout: Duration::from_secs(5),
            max_concurrency: 8,
            window_size: 32,
            max_nodes_per_batch: 128,
        }
    }

    pub(crate) fn valid(&self) -> bool {
        !self.target.host.is_empty()
            && self.target.host.len() <= 255
            && !self.target.host.chars().any(char::is_control)
            && self.target.port > 0
            && !self.timeout.is_zero()
            && self.timeout <= Duration::from_secs(30)
            && (1..=64).contains(&self.max_concurrency)
            && (1..=128).contains(&self.window_size)
            && (1..=1024).contains(&self.max_nodes_per_batch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitProbeState {
    Unknown,
    Up,
    Degraded,
    Down,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitProbeFailure {
    Timeout,
    Connection,
    TcpUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitProbeObservation {
    pub adapter_ready: bool,
    pub state: TransitProbeState,
    /// TCP tunnel establishment latency, not application response latency.
    pub rtt_ms: Option<u64>,
    pub jitter_ms: Option<u64>,
    pub loss_ppm: Option<u32>,
    /// Connect-only probes do not estimate throughput or capacity.
    pub throughput_bps: Option<u64>,
    pub effective_capacity_bps: Option<u64>,
    pub attempts: u64,
    pub successes: u64,
    pub last_error: Option<TransitProbeFailure>,
    pub observed_at_unix_ms: Option<u64>,
    pub age_ms: Option<u64>,
}

impl Default for TransitProbeObservation {
    fn default() -> Self {
        Self {
            adapter_ready: false,
            state: TransitProbeState::Unknown,
            rtt_ms: None,
            jitter_ms: None,
            loss_ppm: None,
            throughput_bps: None,
            effective_capacity_bps: None,
            attempts: 0,
            successes: 0,
            last_error: None,
            observed_at_unix_ms: None,
            age_ms: None,
        }
    }
}

#[derive(Default)]
pub(crate) struct ProbeStore {
    pub config: Option<TransitProbeConfig>,
    pub cursor: usize,
    samples: BTreeMap<TransitProxyId, Samples>,
    active: BTreeMap<TransitProxyId, watch::Sender<bool>>,
}

pub(crate) struct ProbeCandidate {
    pub id: TransitProxyId,
    pub adapter: Arc<dyn TransitAdapter>,
    pub admission: Option<AdmissionRevocation>,
    pub cancelled: watch::Receiver<bool>,
}

#[derive(Default)]
struct Samples {
    window: VecDeque<Result<u64, TransitProbeFailure>>,
    attempts: u64,
    successes: u64,
    captured: Option<Instant>,
    observed_at_unix_ms: Option<u64>,
}

impl ProbeStore {
    pub fn configure(&mut self, config: Option<TransitProbeConfig>) {
        if self.config != config {
            self.samples.clear();
            self.active.clear();
            self.cursor = 0;
        }
        self.config = config;
    }

    pub fn forget(&mut self, id: &TransitProxyId) {
        self.samples.remove(id);
        self.cancel(id);
    }

    pub fn arm(&mut self, id: &TransitProxyId) -> watch::Receiver<bool> {
        let (sender, receiver) = watch::channel(false);
        self.active.insert(id.clone(), sender);
        receiver
    }

    pub fn cancel(&mut self, id: &TransitProxyId) {
        if let Some(sender) = self.active.remove(id) {
            sender.send_replace(true);
        }
    }

    pub fn finish_batch(&mut self) {
        self.active.clear();
    }

    pub fn record(
        &mut self,
        id: TransitProxyId,
        value: Result<u64, TransitProbeFailure>,
        window_size: usize,
    ) {
        let samples = self.samples.entry(id).or_default();
        samples.attempts = samples.attempts.saturating_add(1);
        samples.successes = samples.successes.saturating_add(u64::from(value.is_ok()));
        samples.window.push_back(value);
        while samples.window.len() > window_size {
            samples.window.pop_front();
        }
        samples.captured = Some(Instant::now());
        samples.observed_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64);
    }

    pub fn observations(
        &self,
        adapters: impl IntoIterator<Item = (TransitProxyId, bool)>,
    ) -> BTreeMap<TransitProxyId, TransitProbeObservation> {
        adapters
            .into_iter()
            .map(|(id, adapter_ready)| {
                let mut observation = TransitProbeObservation {
                    adapter_ready,
                    ..TransitProbeObservation::default()
                };
                if let Some(samples) = self.samples.get(&id) {
                    let attempts = samples.window.len();
                    let failures = samples
                        .window
                        .iter()
                        .filter(|sample| sample.is_err())
                        .count();
                    let successful: Vec<_> = samples
                        .window
                        .iter()
                        .filter_map(|sample| sample.as_ref().ok().copied())
                        .collect();
                    observation.rtt_ms = successful.last().copied();
                    observation.jitter_ms = (successful.len() > 1).then(|| {
                        successful
                            .windows(2)
                            .map(|pair| pair[0].abs_diff(pair[1]))
                            .sum::<u64>()
                            / (successful.len() as u64 - 1)
                    });
                    observation.loss_ppm = (attempts > 0)
                        .then(|| (failures as u64 * 1_000_000 / attempts as u64) as u32);
                    observation.state = match samples.window.back() {
                        Some(Err(_)) => TransitProbeState::Down,
                        Some(Ok(_)) if failures > 0 => TransitProbeState::Degraded,
                        Some(Ok(_)) => TransitProbeState::Up,
                        None => TransitProbeState::Unknown,
                    };
                    observation.last_error = samples
                        .window
                        .back()
                        .and_then(|sample| sample.as_ref().err().copied());
                    observation.attempts = samples.attempts;
                    observation.successes = samples.successes;
                    observation.observed_at_unix_ms = samples.observed_at_unix_ms;
                    observation.age_ms = samples.captured.map(|captured| {
                        captured.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
                    });
                }
                if !adapter_ready {
                    observation.state = TransitProbeState::Unknown;
                }
                (id, observation)
            })
            .collect()
    }
}

pub(crate) async fn probe_batch(
    config: TransitProbeConfig,
    adapters: Vec<ProbeCandidate>,
) -> Vec<(TransitProxyId, Result<u64, TransitProbeFailure>)> {
    let mut pending = adapters.into_iter();
    let mut tasks = JoinSet::new();
    let mut result = Vec::new();
    loop {
        while tasks.len() < config.max_concurrency {
            let Some(ProbeCandidate {
                id,
                adapter,
                admission,
                mut cancelled,
            }) = pending.next()
            else {
                break;
            };
            let target = config.target.clone();
            let duration = config.timeout;
            tasks.spawn(async move {
                if *cancelled.borrow() || admission.as_ref().is_some_and(|token| !token.is_valid())
                {
                    return None;
                }
                let start = Instant::now();
                let outcome = if !adapter.supports_tcp() {
                    Err(TransitProbeFailure::TcpUnavailable)
                } else {
                    tokio::select! {
                        biased;
                        _ = cancelled.changed() => return None,
                        result = timeout(duration, adapter.connect(ConnectRequest {
                            destination: target,
                        })) => {
                            match result {
                                Ok(Ok(connection)) => {
                                    drop(connection);
                                    Ok(start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64)
                                }
                                Ok(Err(_)) => Err(TransitProbeFailure::Connection),
                                Err(_) => Err(TransitProbeFailure::Timeout),
                            }
                        }
                    }
                };
                if *cancelled.borrow() || admission.as_ref().is_some_and(|token| !token.is_valid())
                {
                    None
                } else {
                    Some((id, outcome))
                }
            });
        }
        match tasks.join_next().await {
            Some(Ok(Some(value))) => result.push(value),
            Some(Ok(None) | Err(_)) => {}
            None => break,
        }
    }
    result
}

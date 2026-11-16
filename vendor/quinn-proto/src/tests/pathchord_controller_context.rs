//! Regression tests for PathChord's per-packet controller context hook.

use super::*;
use crate::congestion::{Controller, ControllerFactory, RttEstimator};

#[derive(Default)]
struct Observed {
    switched: bool,
    acknowledged: Vec<u8>,
    lost: Vec<u8>,
}

struct Factory(Arc<Mutex<Observed>>);

impl ControllerFactory for Factory {
    fn build(self: Arc<Self>, _now: Instant, _mtu: u16) -> Box<dyn Controller> {
        Box::new(Capture(self.0.clone()))
    }
}

#[derive(Clone)]
struct Capture(Arc<Mutex<Observed>>);

impl Controller for Capture {
    fn packet_context(&self) -> u8 {
        u8::from(self.0.lock().unwrap().switched)
    }

    fn on_ack_with_context(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        _rtt: &RttEstimator,
        context: u8,
    ) {
        self.0.lock().unwrap().acknowledged.push(context);
    }

    fn on_packet_lost(&mut self, _now: Instant, context: u8) {
        self.0.lock().unwrap().lost.push(context);
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _persistent: bool,
        _bytes: u64,
    ) {
    }

    fn on_mtu_update(&mut self, _mtu: u16) {}

    fn window(&self) -> u64 {
        1_000_000
    }

    fn initial_window(&self) -> u64 {
        self.window()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

fn exercise_pre_switch_packet(drop_old: bool) {
    let observed = Arc::new(Mutex::new(Observed::default()));
    let mut transport = TransportConfig::default();
    transport.congestion_controller_factory(Arc::new(Factory(observed.clone())));
    transport.mtu_discovery_config(None);
    let mut config = client_config();
    config.transport_config(Arc::new(transport));
    let mut pair = Pair::default();
    let (client, _) = pair.connect_with(config);
    {
        let mut state = observed.lock().unwrap();
        state.acknowledged.clear();
        state.lost.clear();
    }

    pair.client_conn_mut(client).ping();
    pair.drive_client();
    let old_packets = std::mem::take(&mut pair.server.inbound);
    assert!(!old_packets.is_empty());
    observed.lock().unwrap().switched = true;
    for _ in 0..5 {
        pair.client_conn_mut(client).ping();
        pair.drive_client();
    }
    assert!(!pair.server.inbound.is_empty());
    if !drop_old {
        // Deliver the old datagram after the newer ones, forcing reordering.
        pair.server.inbound.extend(old_packets);
    }
    pair.drive();

    let state = observed.lock().unwrap();
    assert!(state.acknowledged.contains(&1));
    if drop_old {
        assert!(
            state.lost.contains(&0),
            "pre-switch packet loss must retain context zero"
        );
    } else {
        assert!(
            state.acknowledged.contains(&0),
            "delayed pre-switch ACK must retain context zero"
        );
    }
}

#[test]
fn delayed_pre_switch_acks_keep_their_original_context() {
    exercise_pre_switch_packet(false);
}

#[test]
fn delayed_pre_switch_losses_keep_their_original_context() {
    exercise_pre_switch_packet(true);
}

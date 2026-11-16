//! Hysteria2's post-authentication Brutal congestion controller.
//!
//! The formulas and packet-bucket pacing follow sing-quic's Brutal sender.
//! The vendored Quinn hooks let it own pacing while all other controllers keep
//! Quinn's normal send path. Each QUIC connection owns its switch and samples.

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use quinn::congestion::{
    BbrConfig, Controller, ControllerFactory, ControllerMetrics, RttEstimator,
};

const NS_PER_SECOND: u128 = 1_000_000_000;
const MIN_PACING_DELAY: Duration = Duration::from_millis(1);
const SLOT_COUNT: usize = 5;

#[derive(Clone, Copy, Default)]
struct Slot {
    second: Option<u64>,
    acked: u64,
    lost: u64,
}

#[derive(Clone)]
struct Samples {
    epoch: Instant,
    slots: [Slot; SLOT_COUNT],
    acked: u64,
    total: u64,
}

impl Samples {
    fn new(now: Instant) -> Self {
        Self {
            epoch: now,
            slots: [Slot::default(); SLOT_COUNT],
            acked: 1,
            total: 1,
        }
    }

    fn record(&mut self, now: Instant, acked: u64, lost: u64) {
        let second = now.saturating_duration_since(self.epoch).as_secs();
        let slot = &mut self.slots[(second % SLOT_COUNT as u64) as usize];
        if slot.second != Some(second) {
            *slot = Slot {
                second: Some(second),
                ..Slot::default()
            };
        }
        slot.acked = slot.acked.saturating_add(acked);
        slot.lost = slot.lost.saturating_add(lost);
        let (acked, lost) = self
            .slots
            .iter()
            .filter(|slot| slot.second.is_some_and(|s| second.saturating_sub(s) <= 5))
            .fold((0_u64, 0_u64), |(acks, losses), slot| {
                (
                    acks.saturating_add(slot.acked),
                    losses.saturating_add(slot.lost),
                )
            });
        let total = acked.saturating_add(lost);
        (self.acked, self.total) = if total < 50 {
            (1, 1)
        } else if u128::from(acked) * 5 < u128::from(total) * 4 {
            (4, 5)
        } else {
            (acked, total)
        };
    }

    fn rate(&self, target: u64) -> u64 {
        saturating_u64(u128::from(target) * u128::from(self.total) / u128::from(self.acked))
    }

    fn window(&self, target: u64, rtt: Option<Duration>) -> u64 {
        let Some(rtt) = rtt.filter(|rtt| !rtt.is_zero()) else {
            return 10_240;
        };
        let numerator = u128::from(self.rate(target))
            .saturating_mul(rtt.as_nanos())
            .saturating_mul(2);
        saturating_u64(numerator / NS_PER_SECOND).max(1)
    }
}

fn saturating_u64(value: u128) -> u64 {
    value.min(u128::from(u64::MAX)) as u64
}

#[derive(Clone, Default)]
struct Pacer {
    last_sent: Option<Instant>,
    budget_after_send: u64,
}

impl Pacer {
    fn capacity(rate: u64, mtu: u16) -> u64 {
        saturating_u64(u128::from(rate) * 4 / 1_000).max(u64::from(mtu) * 10)
    }

    fn budget(&self, now: Instant, rate: u64, mtu: u16) -> u64 {
        let capacity = Self::capacity(rate, mtu);
        let Some(last) = self.last_sent else {
            return capacity;
        };
        let added = u128::from(rate).saturating_mul(now.saturating_duration_since(last).as_nanos())
            / NS_PER_SECOND;
        self.budget_after_send
            .saturating_add(saturating_u64(added))
            .min(capacity)
    }

    fn transmitted(&mut self, now: Instant, bytes: u64, rate: u64, mtu: u16) {
        self.budget_after_send = self.budget(now, rate, mtu).saturating_sub(bytes);
        self.last_sent = Some(now);
    }

    fn deadline(&self, now: Instant, required: u64, rate: u64, mtu: u16) -> Option<Instant> {
        if self.budget(now, rate, mtu) >= required {
            return None;
        }
        // A nonzero Brutal target always yields a nonzero rate. Saturating the
        // arithmetic keeps hostile configuration values from overflowing.
        let deficit = required.saturating_sub(self.budget_after_send);
        let nanos = (u128::from(deficit) * NS_PER_SECOND).div_ceil(u128::from(rate));
        let delay = Duration::from_nanos(saturating_u64(nanos)).max(MIN_PACING_DELAY);
        let last = self.last_sent.unwrap_or(now);
        last.checked_add(delay).or_else(|| now.checked_add(delay))
    }
}

pub(super) struct BrutalFactory {
    target: Arc<AtomicU64>,
}

impl BrutalFactory {
    pub(super) fn new() -> Self {
        Self {
            target: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl ControllerFactory for BrutalFactory {
    fn build(self: Arc<Self>, now: Instant, mtu: u16) -> Box<dyn Controller> {
        Box::new(BrutalController {
            target: self.target.clone(),
            bbr: Arc::new(BbrConfig::default()).build(now, mtu),
            samples: Samples::new(now),
            pacer: Pacer::default(),
            rtt: None,
            mtu,
        })
    }
}

pub(super) struct BrutalController {
    target: Arc<AtomicU64>,
    bbr: Box<dyn Controller>,
    samples: Samples,
    pacer: Pacer,
    rtt: Option<Duration>,
    mtu: u16,
}

impl BrutalController {
    pub(super) fn enable(&self, bytes_per_second: u64) {
        self.target.store(bytes_per_second, Ordering::Release);
    }

    pub(super) fn target(&self) -> u64 {
        self.target.load(Ordering::Acquire)
    }

    fn record_ack(&mut self, now: Instant, context: u8) {
        if context != 0 {
            self.samples.record(now, 1, 0);
        }
    }

    #[cfg(test)]
    pub(super) fn sample_ratio(&self) -> (u64, u64) {
        (self.samples.acked, self.samples.total)
    }
}

impl Controller for BrutalController {
    fn can_send(
        &self,
        in_flight: u64,
        next_datagram: u64,
        untracked: u64,
        rtt: &RttEstimator,
    ) -> bool {
        let target = self.target();
        if target == 0 {
            self.bbr.can_send(in_flight, next_datagram, untracked, rtt)
        } else {
            in_flight.saturating_add(untracked) < self.samples.window(target, rtt.smoothed())
        }
    }

    fn pacing_deadline(&self, now: Instant, required: u64) -> Option<Option<Instant>> {
        let target = self.target();
        (target != 0).then(|| {
            self.pacer
                .deadline(now, required, self.samples.rate(target), self.mtu)
        })
    }

    fn packet_context(&self) -> u8 {
        u8::from(self.target() != 0)
    }

    fn on_packet_transmitted(&mut self, now: Instant, bytes: u64, context: u8) {
        let target = self.target();
        if context != 0 && target != 0 {
            self.pacer
                .transmitted(now, bytes, self.samples.rate(target), self.mtu);
        }
    }

    fn on_packet_lost(&mut self, now: Instant, context: u8) {
        if self.target() != 0 && context != 0 {
            self.samples.record(now, 0, 1);
        }
    }

    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        if self.target() == 0 {
            self.bbr.on_sent(now, bytes, last_packet_number);
        }
    }

    fn on_ack_with_context(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
        context: u8,
    ) {
        self.rtt = rtt.smoothed();
        if self.target() == 0 {
            self.bbr.on_ack(now, sent, bytes, app_limited, rtt);
        } else {
            self.record_ack(now, context);
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest: Option<u64>,
    ) {
        if self.target() == 0 {
            self.bbr.on_end_acks(now, in_flight, app_limited, largest);
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        persistent: bool,
        lost_bytes: u64,
    ) {
        if self.target() == 0 {
            self.bbr
                .on_congestion_event(now, sent, persistent, lost_bytes);
        }
    }

    fn on_mtu_update(&mut self, mtu: u16) {
        self.mtu = mtu;
        self.bbr.on_mtu_update(mtu);
    }

    fn window(&self) -> u64 {
        let target = self.target();
        if target == 0 {
            self.bbr.window()
        } else {
            self.samples.window(target, self.rtt)
        }
    }

    fn initial_window(&self) -> u64 {
        if self.target() == 0 {
            self.bbr.initial_window()
        } else {
            self.window()
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        let target = self.target();
        if target == 0 {
            self.bbr.metrics()
        } else {
            let mut metrics = ControllerMetrics::default();
            metrics.congestion_window = self.window();
            metrics.pacing_rate = Some(self.samples.rate(target).saturating_mul(8));
            metrics
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            target: self.target.clone(),
            bbr: self.bbr.clone_box(),
            samples: self.samples.clone(),
            pacer: self.pacer.clone(),
            rtt: self.rtt,
            mtu: self.mtu,
        })
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_samples_age_and_clamp_only_after_fifty_packets() {
        let start = Instant::now();
        let mut samples = Samples::new(start);
        samples.record(start, 39, 10);
        assert_eq!(samples.rate(1_000), 1_000);
        samples.record(start, 1, 0);
        assert_eq!(samples.rate(1_000), 1_250);
        samples.record(start + Duration::from_secs(1), 100, 0);
        assert_eq!(samples.rate(1_000), 1_071);
        samples.record(start + Duration::from_secs(6), 1, 0);
        assert_eq!(samples.rate(1_000), 1_000);

        samples.record(start + Duration::from_secs(6), 0, 100);
        assert_eq!(samples.rate(1_000), 1_250);
        assert_eq!(samples.window(125_000, None), 10_240);
        assert_eq!(
            samples.window(125_000, Some(Duration::from_millis(100))),
            31_250
        );
        assert_eq!(samples.rate(u64::MAX), u64::MAX);
        assert_eq!(samples.window(u64::MAX, Some(Duration::MAX)), u64::MAX);
        assert_eq!(samples.window(1, Some(Duration::from_micros(1))), 1);
    }

    #[test]
    fn pacer_enforces_rate_with_burst_idle_and_mtu_changes() {
        let start = Instant::now();
        let rate = 125_000;
        let mut pacer = Pacer::default();
        assert_eq!(pacer.budget(start, rate, 1_200), 12_000);
        for _ in 0..10 {
            assert_eq!(pacer.deadline(start, 1_200, rate, 1_200), None);
            pacer.transmitted(start, 1_200, rate, 1_200);
        }
        assert_eq!(
            pacer.deadline(start, 1_200, rate, 1_200),
            Some(start + Duration::from_micros(9_600))
        );
        let next = start + Duration::from_micros(9_600);
        assert_eq!(pacer.deadline(next, 1_200, rate, 1_200), None);
        pacer.transmitted(next, 1_200, rate, 1_200);
        assert_eq!(
            pacer.budget(next + Duration::from_secs(2), rate, 1_400),
            14_000
        );
        assert_eq!(Pacer::capacity(10_000_000, 1_200), 40_000);
        assert_eq!(Pacer::capacity(u64::MAX, 1_200), u64::MAX / 250);
    }

    #[test]
    fn pacer_reserves_a_pending_packet_and_rounds_small_delays() {
        let start = Instant::now();
        let mut pacer = Pacer::default();
        for _ in 0..9 {
            pacer.transmitted(start, 1_200, 2_000_000, 1_200);
        }
        assert!(pacer.deadline(start, 1_200, 2_000_000, 1_200).is_none());
        assert_eq!(
            pacer.deadline(start, 2_400, 2_000_000, 1_200),
            Some(start + Duration::from_millis(1))
        );
    }

    #[test]
    fn controller_switch_is_per_connection_and_clones_share_only_its_switch() {
        let now = Instant::now();
        let first = Arc::new(BrutalFactory::new()).build(now, 1_200);
        let second = Arc::new(BrutalFactory::new()).build(now, 1_200);
        assert!(first.pacing_deadline(now, 1_200).is_none());
        assert!(second.pacing_deadline(now, 1_200).is_none());
        let handle = first
            .clone_box()
            .into_any()
            .downcast::<BrutalController>()
            .unwrap();
        handle.enable(125_000);
        assert_eq!(first.pacing_deadline(now, 1_200), Some(None));
        assert!(second.pacing_deadline(now, 1_200).is_none());
    }

    #[test]
    fn ecn_is_not_counted_as_a_lost_packet() {
        let now = Instant::now();
        let mut controller = Arc::new(BrutalFactory::new())
            .build(now, 1_200)
            .into_any()
            .downcast::<BrutalController>()
            .unwrap();
        controller.enable(125_000);
        controller.samples.record(now, 40, 9);
        controller.on_congestion_event(now, now, false, 0);
        assert_eq!(controller.sample_ratio(), (1, 1));
        controller.on_packet_lost(now, 1);
        assert_eq!(controller.sample_ratio(), (40, 50));
    }

    #[test]
    fn delayed_pre_switch_acknowledgements_and_losses_are_not_sampled() {
        let now = Instant::now();
        let mut controller = Arc::new(BrutalFactory::new())
            .build(now, 1_200)
            .into_any()
            .downcast::<BrutalController>()
            .unwrap();
        let old_context = controller.packet_context();
        controller.enable(125_000);
        let new_context = controller.packet_context();
        assert_ne!(old_context, new_context);

        controller.on_packet_transmitted(now, 1_200, old_context);
        assert!(controller.pacer.last_sent.is_none());
        controller.on_packet_transmitted(now, 1_200, new_context);
        assert_eq!(controller.pacer.last_sent, Some(now));

        // Events for an older packet can arrive after newer packets.
        controller.record_ack(now, new_context);
        controller.on_packet_lost(now, new_context);
        controller.record_ack(now, old_context);
        controller.on_packet_lost(now, old_context);
        assert_eq!(controller.samples.slots[0].acked, 1);
        assert_eq!(controller.samples.slots[0].lost, 1);
    }
}

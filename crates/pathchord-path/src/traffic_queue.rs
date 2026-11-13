//! Weighted fair selection among backlogged classes and round-robin flows.
use pathchord_core::TrafficClassConfig;
use std::collections::{BTreeMap, BTreeSet};

const SCALE: u128 = 1_000_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum FlowKey {
    Tcp(u64),
    Udp(u64),
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ClassKey(String, u8, u32);
#[derive(Default)]
pub(crate) struct TrafficQueue {
    finish: BTreeMap<ClassKey, u128>,
    last: BTreeMap<ClassKey, FlowKey>,
    virtual_time: u128,
}
impl TrafficQueue {
    pub(crate) fn select(
        &mut self,
        ready: &[(FlowKey, Option<TrafficClassConfig>, usize)],
        quantum: usize,
    ) -> Option<FlowKey> {
        let mut classes: BTreeMap<ClassKey, Vec<(FlowKey, usize)>> = BTreeMap::new();
        for (flow, profile, bytes) in ready {
            let key = profile.as_ref().map_or_else(
                || ClassKey("default".into(), 0, 1),
                |p| ClassKey(p.name.clone(), p.priority, p.share.max(1)),
            );
            classes.entry(key).or_default().push((*flow, *bytes));
        }
        let active: BTreeSet<_> = classes.keys().cloned().collect();
        self.finish.retain(|key, _| active.contains(key));
        self.last.retain(|key, _| active.contains(key));
        for key in &active {
            self.finish.entry(key.clone()).or_insert(self.virtual_time);
        }
        let total_share: u128 = classes.keys().map(|key| u128::from(key.2)).sum();
        let mut candidates = Vec::new();
        for (key, mut flows) in classes {
            flows.sort_by_key(|(flow, _)| *flow);
            let (flow, bytes) = self
                .last
                .get(&key)
                .and_then(|last| flows.iter().find(|(flow, _)| flow > last))
                .copied()
                .unwrap_or(flows[0]);
            let start = self
                .finish
                .get(&key)
                .copied()
                .unwrap_or(self.virtual_time)
                .max(self.virtual_time);
            let finish =
                start.saturating_add((bytes.max(1) as u128 * SCALE).div_ceil(u128::from(key.2)));
            candidates.push((key, flow, finish));
        }
        let minimum = candidates.iter().map(|(_, _, finish)| *finish).min()?;
        // Priority can advance at most one aggregate byte quantum, so a
        // continuously backlogged low-priority class still makes progress.
        let allowance = (quantum as u128 * SCALE).div_ceil(total_share.max(1));
        candidates.retain(|(_, _, finish)| *finish <= minimum.saturating_add(allowance));
        candidates.sort_by(|(a, fa, va), (b, fb, vb)| {
            b.1.cmp(&a.1)
                .then_with(|| va.cmp(vb))
                .then_with(|| fa.cmp(fb))
        });
        let (key, flow, finish) = candidates.into_iter().next()?;
        self.virtual_time = self.virtual_time.max(
            self.finish
                .values()
                .copied()
                .min()
                .unwrap_or(self.virtual_time),
        );
        self.finish.insert(key.clone(), finish);
        self.last.insert(key, flow);
        Some(flow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn class(name: &str, priority: u8, share: u32) -> Option<TrafficClassConfig> {
        Some(TrafficClassConfig {
            name: name.into(),
            priority,
            share,
        })
    }
    #[test]
    fn shares_are_per_class_and_priority_cannot_starve_lower_classes() {
        let mut queue = TrafficQueue::default();
        let mut count = [0; 4];
        let ready = vec![
            (FlowKey::Tcp(0), class("high", 255, 3), 1024),
            (FlowKey::Tcp(1), class("low", 0, 1), 1024),
            (FlowKey::Tcp(2), class("low", 0, 1), 1024),
            (FlowKey::Udp(3), class("low", 0, 1), 1024),
        ];
        for _ in 0..4000 {
            match queue.select(&ready, 1024).unwrap() {
                FlowKey::Tcp(i) => count[i as usize] += 1,
                FlowKey::Udp(i) => count[i as usize] += 1,
            }
        }
        assert!((2990..=3010).contains(&count[0]), "{count:?}");
        for value in &count[1..] {
            assert!((325..=340).contains(value), "{count:?}");
        }
    }
    #[test]
    fn high_priority_gets_a_bounded_initial_latency_advantage() {
        let mut queue = TrafficQueue::default();
        let ready = [
            (FlowKey::Tcp(1), class("low", 0, 1), 100),
            (FlowKey::Tcp(2), class("high", 255, 1), 100),
        ];
        assert_eq!(queue.select(&ready, 100), Some(FlowKey::Tcp(2)));
        assert_eq!(queue.select(&ready, 100), Some(FlowKey::Tcp(1)));
    }
}

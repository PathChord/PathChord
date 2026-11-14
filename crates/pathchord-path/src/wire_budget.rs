use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

/// Scheduler priority for the aggregate Egress wire budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WirePriority {
    Primary,
    Retransmission,
    RequiredControl,
    OptionalReplication,
}

#[derive(Debug)]
struct BudgetState {
    window_started: Instant,
    consumed_bytes: u64,
}

/// A bounded one-second aggregate wire budget.
///
/// Primary traffic, ordinary retransmission, and required control reserve from
/// the same hard cap. Optional replication is admitted only while residual
/// capacity remains, so it can fall to zero without blocking reliability.
#[derive(Debug)]
pub struct WireBudget {
    capacity_bytes_per_second: u64,
    state: Mutex<BudgetState>,
}

impl WireBudget {
    #[must_use]
    pub fn new(capacity_bps: u64) -> Option<Self> {
        let capacity_bytes_per_second = capacity_bps / 8;
        (capacity_bytes_per_second > 0).then(|| Self {
            capacity_bytes_per_second,
            state: Mutex::new(BudgetState {
                window_started: Instant::now(),
                consumed_bytes: 0,
            }),
        })
    }

    #[must_use]
    pub fn capacity_bytes_per_second(&self) -> u64 {
        self.capacity_bytes_per_second
    }

    pub fn try_reserve(&self, priority: WirePriority, bytes: u64) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.window_started.elapsed() >= Duration::from_secs(1) {
            state.window_started = Instant::now();
            state.consumed_bytes = 0;
        }
        let next = state.consumed_bytes.saturating_add(bytes);
        if next > self.capacity_bytes_per_second {
            return false;
        }
        if priority == WirePriority::OptionalReplication
            && self
                .capacity_bytes_per_second
                .saturating_sub(state.consumed_bytes)
                < bytes
        {
            return false;
        }
        state.consumed_bytes = next;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_replication_uses_only_residual_capacity() {
        let budget = WireBudget::new(8_000).expect("one thousand bytes per second");
        assert!(budget.try_reserve(WirePriority::Primary, 900));
        assert!(budget.try_reserve(WirePriority::OptionalReplication, 100));
        assert!(!budget.try_reserve(WirePriority::OptionalReplication, 1));
        assert!(!budget.try_reserve(WirePriority::Primary, 1));
    }

    #[test]
    fn ordinary_retransmission_and_control_share_the_hard_cap() {
        let budget = WireBudget::new(8_000).expect("one thousand bytes per second");
        assert!(budget.try_reserve(WirePriority::Retransmission, 500));
        assert!(budget.try_reserve(WirePriority::RequiredControl, 500));
        assert!(!budget.try_reserve(WirePriority::Primary, 1));
    }
}

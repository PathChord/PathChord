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
    primary_bytes: u64,
    recovery_bytes: u64,
    optional_bytes: u64,
    total_reserved_bytes: u64,
}

impl BudgetState {
    fn consumed_bytes(&self) -> u64 {
        self.primary_bytes
            .saturating_add(self.recovery_bytes)
            .saturating_add(self.optional_bytes)
    }
}

/// A bounded one-second aggregate wire budget.
///
/// Primary traffic, ordinary retransmission, and required control reserve from
/// the same hard cap. Optional replication is admitted only while residual
/// capacity remains, so it can fall to zero without blocking reliability.
#[derive(Debug)]
pub struct WireBudget {
    capacity_bytes_per_second: u64,
    primary_reserve_bytes: u64,
    recovery_reserve_bytes: u64,
    state: Mutex<BudgetState>,
}

impl WireBudget {
    #[must_use]
    pub fn new(capacity_bps: u64) -> Option<Self> {
        let capacity_bytes_per_second = capacity_bps / 8;
        (capacity_bytes_per_second > 0).then(|| {
            let reserve = (capacity_bytes_per_second / 8).min(capacity_bytes_per_second / 2);
            Self {
                primary_reserve_bytes: reserve,
                recovery_reserve_bytes: reserve,
                capacity_bytes_per_second,
                state: Mutex::new(BudgetState {
                    window_started: Instant::now(),
                    primary_bytes: 0,
                    recovery_bytes: 0,
                    optional_bytes: 0,
                    total_reserved_bytes: 0,
                }),
            }
        })
    }

    #[must_use]
    pub fn capacity_bytes_per_second(&self) -> u64 {
        self.capacity_bytes_per_second
    }

    /// Monotonic number of wire bytes admitted since construction. Consumers
    /// can take deltas without depending on the one-second accounting window.
    #[must_use]
    pub fn total_reserved_bytes(&self) -> u64 {
        self.state
            .lock()
            .map(|state| state.total_reserved_bytes)
            .unwrap_or(0)
    }

    #[must_use]
    pub fn remaining_bytes(&self) -> u64 {
        let Ok(state) = self.state.lock() else {
            return 0;
        };
        if state.window_started.elapsed() >= Duration::from_secs(1) {
            self.capacity_bytes_per_second
        } else {
            self.capacity_bytes_per_second
                .saturating_sub(state.consumed_bytes())
        }
    }

    #[must_use]
    pub fn optional_replication_remaining_bytes(&self) -> u64 {
        let Ok(state) = self.state.lock() else {
            return 0;
        };
        let (primary_bytes, recovery_bytes, optional_bytes) =
            if state.window_started.elapsed() >= Duration::from_secs(1) {
                (0, 0, 0)
            } else {
                (
                    state.primary_bytes,
                    state.recovery_bytes,
                    state.optional_bytes,
                )
            };
        let primary_overflow = primary_bytes.saturating_sub(self.primary_reserve_bytes);
        let recovery_overflow = recovery_bytes.saturating_sub(self.recovery_reserve_bytes);
        self.capacity_bytes_per_second
            .saturating_sub(self.primary_reserve_bytes)
            .saturating_sub(self.recovery_reserve_bytes)
            .saturating_sub(primary_overflow)
            .saturating_sub(recovery_overflow)
            .saturating_sub(optional_bytes)
    }

    pub fn try_reserve(&self, priority: WirePriority, bytes: u64) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.window_started.elapsed() >= Duration::from_secs(1) {
            state.window_started = Instant::now();
            state.primary_bytes = 0;
            state.recovery_bytes = 0;
            state.optional_bytes = 0;
        }
        let consumed = state.consumed_bytes();
        let next = consumed.saturating_add(bytes);
        let (primary, recovery, optional) = match priority {
            WirePriority::Primary => (
                state.primary_bytes.saturating_add(bytes),
                state.recovery_bytes,
                state.optional_bytes,
            ),
            WirePriority::Retransmission | WirePriority::RequiredControl => (
                state.primary_bytes,
                state.recovery_bytes.saturating_add(bytes),
                state.optional_bytes,
            ),
            WirePriority::OptionalReplication => (
                state.primary_bytes,
                state.recovery_bytes,
                state.optional_bytes.saturating_add(bytes),
            ),
        };
        let preserve_primary = self.primary_reserve_bytes.saturating_sub(primary);
        let preserve_recovery = self.recovery_reserve_bytes.saturating_sub(recovery);
        let allowed = match priority {
            WirePriority::Primary => next.saturating_add(preserve_recovery),
            WirePriority::Retransmission | WirePriority::RequiredControl => {
                next.saturating_add(preserve_primary)
            }
            WirePriority::OptionalReplication => next
                .saturating_add(preserve_primary)
                .saturating_add(preserve_recovery),
        };
        if allowed > self.capacity_bytes_per_second {
            return false;
        }
        state.primary_bytes = primary;
        state.recovery_bytes = recovery;
        state.optional_bytes = optional;
        state.total_reserved_bytes = state.total_reserved_bytes.saturating_add(bytes);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_replication_uses_only_residual_capacity() {
        let budget = WireBudget::new(8_000).expect("one thousand bytes per second");
        assert!(budget.try_reserve(WirePriority::Primary, 850));
        assert!(budget.try_reserve(WirePriority::OptionalReplication, 25));
        assert!(!budget.try_reserve(WirePriority::OptionalReplication, 1));
        assert!(budget.try_reserve(WirePriority::Retransmission, 100));
    }

    #[test]
    fn ordinary_retransmission_and_control_share_the_hard_cap() {
        let budget = WireBudget::new(8_000).expect("one thousand bytes per second");
        assert!(budget.try_reserve(WirePriority::Primary, 875));
        assert!(budget.try_reserve(WirePriority::Retransmission, 100));
        assert!(budget.try_reserve(WirePriority::RequiredControl, 25));
        assert!(!budget.try_reserve(WirePriority::Primary, 1));
    }
}

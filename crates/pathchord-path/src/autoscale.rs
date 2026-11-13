#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathAutoscalerConfig {
    pub min_paths: usize,
    pub max_paths: usize,
    pub scale_out_utilization_basis_points: u16,
    pub scale_in_utilization_basis_points: u16,
    pub recovery_samples: u32,
    pub scale_in_samples: u32,
    pub scale_in_cooldown_ms: u64,
}

impl Default for PathAutoscalerConfig {
    fn default() -> Self {
        Self {
            min_paths: 1,
            max_paths: 4,
            scale_out_utilization_basis_points: 8_000,
            scale_in_utilization_basis_points: 3_500,
            recovery_samples: 3,
            scale_in_samples: 6,
            scale_in_cooldown_ms: 30_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoscaleInput {
    pub demand_bps: u64,
    pub effective_capacity_bps: u64,
    pub ready_paths: usize,
    pub degraded_paths: usize,
    pub recommended_path_count: Option<usize>,
    pub hard_available: bool,
    pub quota_remaining: Option<u64>,
    pub traffic_multiplier_basis_points: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoscaleDecision {
    Add { count: usize },
    Drain { count: usize },
    Hold,
}

#[derive(Debug, Clone)]
pub struct PathAutoscaler {
    config: PathAutoscalerConfig,
    recovery_streak: u32,
    low_utilization_streak: u32,
    last_scale_in_ms: Option<u64>,
}

impl PathAutoscaler {
    pub fn new(config: PathAutoscalerConfig) -> Result<Self, &'static str> {
        if config.min_paths == 0
            || config.max_paths < config.min_paths
            || config.scale_in_utilization_basis_points >= config.scale_out_utilization_basis_points
            || config.scale_out_utilization_basis_points > 10_000
            || config.recovery_samples == 0
            || config.scale_in_samples == 0
        {
            return Err("invalid Path autoscaler configuration");
        }
        Ok(Self {
            config,
            recovery_streak: 0,
            low_utilization_streak: 0,
            last_scale_in_ms: None,
        })
    }

    #[must_use]
    pub const fn config(&self) -> PathAutoscalerConfig {
        self.config
    }

    pub fn evaluate(&mut self, input: AutoscaleInput, now_ms: u64) -> AutoscaleDecision {
        if !input.hard_available {
            self.recovery_streak = 0;
            self.low_utilization_streak = 0;
            return if input.ready_paths == 0 {
                AutoscaleDecision::Hold
            } else {
                AutoscaleDecision::Drain {
                    count: input.ready_paths,
                }
            };
        }
        let multiplier = input.traffic_multiplier_basis_points.max(1);
        let adjusted_capacity = input
            .effective_capacity_bps
            .saturating_mul(u64::from(multiplier))
            / 10_000;
        let adjusted_capacity = if input.quota_remaining == Some(0) {
            adjusted_capacity.saturating_mul(1_000) / 10_000
        } else {
            adjusted_capacity
        };
        let utilization = if adjusted_capacity == 0 {
            if input.demand_bps == 0 { 0 } else { 10_000 }
        } else {
            input
                .demand_bps
                .saturating_mul(10_000)
                .saturating_div(adjusted_capacity)
                .min(10_000)
        };

        if input.degraded_paths > 0 {
            self.recovery_streak = 0;
        } else {
            self.recovery_streak = self.recovery_streak.saturating_add(1);
        }

        let target_paths = input
            .recommended_path_count
            .unwrap_or(self.config.min_paths)
            .max(self.config.min_paths)
            .min(self.config.max_paths);
        if (utilization > u64::from(self.config.scale_out_utilization_basis_points)
            || input.ready_paths < target_paths
            || input.degraded_paths > 0)
            && input.ready_paths < self.config.max_paths
        {
            self.recovery_streak = 0;
            self.low_utilization_streak = 0;
            let minimum_add = target_paths.saturating_sub(input.ready_paths).max(1);
            let capacity_per_path = adjusted_capacity
                .checked_div(input.ready_paths.max(1) as u64)
                .unwrap_or(0)
                .max(1);
            let demanded_paths = input
                .demand_bps
                .saturating_add(capacity_per_path - 1)
                .saturating_div(capacity_per_path) as usize;
            let count = demanded_paths
                .saturating_sub(input.ready_paths)
                .max(minimum_add)
                .min(self.config.max_paths - input.ready_paths);
            return AutoscaleDecision::Add { count };
        }

        if utilization < u64::from(self.config.scale_in_utilization_basis_points)
            && input.ready_paths > self.config.min_paths
            && self.recovery_streak >= self.config.recovery_samples
        {
            self.low_utilization_streak = self.low_utilization_streak.saturating_add(1);
        } else {
            self.low_utilization_streak = 0;
        }
        let cooldown_elapsed = self
            .last_scale_in_ms
            .is_none_or(|last| now_ms.saturating_sub(last) >= self.config.scale_in_cooldown_ms);
        if self.low_utilization_streak >= self.config.scale_in_samples && cooldown_elapsed {
            self.low_utilization_streak = 0;
            self.last_scale_in_ms = Some(now_ms);
            return AutoscaleDecision::Drain { count: 1 };
        }
        AutoscaleDecision::Hold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(demand: u64, capacity: u64, paths: usize) -> AutoscaleInput {
        AutoscaleInput {
            demand_bps: demand,
            effective_capacity_bps: capacity,
            ready_paths: paths,
            degraded_paths: 0,
            recommended_path_count: None,
            hard_available: true,
            quota_remaining: None,
            traffic_multiplier_basis_points: 10_000,
        }
    }

    #[test]
    fn scale_out_is_aggressive_but_scale_in_requires_hysteresis() {
        let mut scaler = PathAutoscaler::new(PathAutoscalerConfig {
            recovery_samples: 2,
            scale_in_samples: 3,
            scale_in_cooldown_ms: 1_000,
            ..PathAutoscalerConfig::default()
        })
        .unwrap();
        assert!(matches!(
            scaler.evaluate(input(900, 1_000, 1), 0),
            AutoscaleDecision::Add { count: 1.. }
        ));
        for now in [100, 200, 300, 400] {
            let decision = scaler.evaluate(input(100, 2_000, 2), now);
            if now < 400 {
                assert_eq!(decision, AutoscaleDecision::Hold);
            } else {
                assert_eq!(decision, AutoscaleDecision::Drain { count: 1 });
            }
        }
        assert_eq!(
            scaler.evaluate(input(100, 2_000, 2), 500),
            AutoscaleDecision::Hold
        );
    }

    #[test]
    fn quota_uses_capacity_floor_multiplier_scales_capacity_and_hard_state_drains() {
        let mut scaler = PathAutoscaler::new(PathAutoscalerConfig::default()).unwrap();
        let mut sample = input(100, 1_000, 2);
        sample.quota_remaining = Some(0);
        assert!(matches!(
            scaler.evaluate(sample, 0),
            AutoscaleDecision::Add { .. }
        ));
        sample.quota_remaining = Some(1);
        sample.demand_bps = 900;
        sample.traffic_multiplier_basis_points = 50_000;
        assert_eq!(scaler.evaluate(sample, 1), AutoscaleDecision::Hold);
        sample.hard_available = false;
        assert_eq!(
            scaler.evaluate(sample, 2),
            AutoscaleDecision::Drain { count: 2 }
        );
    }
}

//! Role startup settings and explicitly configured node probes.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::Endpoint;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EgressServiceSpec {
    pub bind: Option<SocketAddr>,
    pub egress_id: Option<String>,
    pub identity: Option<PathBuf>,
    pub authorization_db: Option<PathBuf>,
    pub control_socket: Option<PathBuf>,
    pub max_concurrent_paths: Option<usize>,
    pub capacity_bps: Option<u64>,
    pub recommended_path_count: Option<u64>,
    pub max_streams_per_ingress: Option<usize>,
    pub quota_remaining: Option<u64>,
    pub traffic_multiplier_basis_points: Option<u32>,
    pub web_bind: Option<SocketAddr>,
    pub web_token_file: Option<PathBuf>,
    #[serde(default)]
    pub web_origins: BTreeSet<String>,
    pub web_protected_transport: Option<bool>,
}

impl EgressServiceSpec {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self
            .egress_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 256 || id.chars().any(char::is_control))
            || [
                self.identity.as_ref(),
                self.authorization_db.as_ref(),
                self.control_socket.as_ref(),
                self.web_token_file.as_ref(),
            ]
            .into_iter()
            .flatten()
            .any(|path| path.as_os_str().is_empty())
        {
            return Err("EgressService contains an invalid identity or path");
        }
        if self.max_concurrent_paths == Some(0)
            || self.max_streams_per_ingress == Some(0)
            || self.recommended_path_count == Some(0)
            || self.traffic_multiplier_basis_points == Some(0)
            || self.max_concurrent_paths.is_some_and(|value| value > 65536)
            || self
                .max_streams_per_ingress
                .is_some_and(|value| value > 1_000_000)
            || self.web_origins.len() > 256
        {
            return Err("EgressService capacity or concurrency settings are invalid");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeProbePolicySpec {
    pub target: Endpoint,
    #[serde(default = "default_interval")]
    pub interval_seconds: u64,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_concurrency")]
    pub max_concurrency: usize,
    #[serde(default = "default_window")]
    pub window_size: usize,
    #[serde(default = "default_batch")]
    pub max_nodes_per_batch: usize,
}
const fn default_interval() -> u64 {
    30
}
const fn default_timeout() -> u64 {
    5
}
const fn default_concurrency() -> usize {
    8
}
const fn default_window() -> usize {
    32
}
const fn default_batch() -> usize {
    128
}

impl NodeProbePolicySpec {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.target.host.is_empty()
            || self.target.host.len() > 255
            || self.target.host.chars().any(char::is_control)
            || self.target.port == 0
            || !(1..=86400).contains(&self.interval_seconds)
            || !(1..=30).contains(&self.timeout_seconds)
            || !(1..=64).contains(&self.max_concurrency)
            || !(1..=128).contains(&self.window_size)
            || !(1..=1024).contains(&self.max_nodes_per_batch)
        {
            return Err("NodeProbePolicy target or bounds are invalid");
        }
        Ok(())
    }
}

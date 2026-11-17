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
    #[serde(default)]
    pub binds: Option<Vec<SocketAddr>>,
    pub egress_id: Option<String>,
    pub identity: Option<PathBuf>,
    pub authorization_db: Option<PathBuf>,
    pub control_socket: Option<PathBuf>,
    pub max_wire_bandwidth_bps: Option<u64>,
    pub max_inbound_target_connections: Option<usize>,
    /// Require names supplied by Ingress to be resolved on Egress instead of
    /// preferring the accompanying address candidates.
    pub remote_dns_only: Option<bool>,
    pub quota_remaining: Option<u64>,
    pub traffic_multiplier_basis_points: Option<u32>,
    #[serde(default)]
    pub web: Option<EgressWebSettings>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EgressWebSettings {
    pub bind: Option<SocketAddr>,
    pub token_file: Option<PathBuf>,
    #[serde(default)]
    pub allowed_origins: BTreeSet<String>,
    pub protected_transport: Option<bool>,
}

impl EgressServiceSpec {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.bind.is_some() && self.binds.is_some() {
            return Err("EgressService bind and binds are mutually exclusive");
        }
        if self.bind.is_some_and(|bind| bind.port() == 0)
            || self.binds.as_ref().is_some_and(|binds| {
                binds.is_empty()
                    || binds.len() > 32
                    || binds.iter().any(|bind| bind.port() == 0)
                    || binds.windows(2).any(|pair| pair[0] == pair[1])
                    || {
                        let mut unique = BTreeSet::new();
                        binds.iter().any(|bind| !unique.insert(*bind))
                    }
            })
        {
            return Err("EgressService bind list is invalid");
        }
        if self
            .egress_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 256 || id.chars().any(char::is_control))
            || [
                self.identity.as_ref(),
                self.authorization_db.as_ref(),
                self.control_socket.as_ref(),
                self.web.as_ref().and_then(|web| web.token_file.as_ref()),
            ]
            .into_iter()
            .flatten()
            .any(|path| path.as_os_str().is_empty())
        {
            return Err("EgressService contains an invalid identity or path");
        }
        if self.max_wire_bandwidth_bps == Some(0)
            || self.max_inbound_target_connections == Some(0)
            || self.traffic_multiplier_basis_points == Some(0)
            || self
                .max_inbound_target_connections
                .is_some_and(|value| value > 1_000_000)
            || self
                .web
                .as_ref()
                .is_some_and(|web| web.allowed_origins.len() > 256)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_nested_web_gateway_settings() {
        let spec: EgressServiceSpec = serde_yaml::from_str(
            "web:\n  bind: 127.0.0.1:9090\n  tokenFile: tokens/admin.token\n  allowedOrigins: [https://admin.example]\n  protectedTransport: true\n",
        )
        .unwrap();
        let web = spec.web.unwrap();
        assert_eq!(web.bind.unwrap().port(), 9090);
        assert_eq!(web.token_file, Some(PathBuf::from("tokens/admin.token")));
        assert_eq!(
            web.allowed_origins,
            BTreeSet::from([String::from("https://admin.example")])
        );
        assert_eq!(web.protected_transport, Some(true));

        let retired: Result<EgressServiceSpec, _> =
            serde_yaml::from_str("webBind: 127.0.0.1:9090\n");
        assert!(retired.is_err());
    }

    #[test]
    fn accepts_multiple_ipv4_and_ipv6_binds() {
        let spec = EgressServiceSpec {
            binds: Some(vec![
                "0.0.0.0:7443".parse().unwrap(),
                "[::]:8443".parse().unwrap(),
            ]),
            ..EgressServiceSpec::default()
        };
        assert_eq!(spec.validate(), Ok(()));
    }

    #[test]
    fn rejects_conflicting_duplicate_or_out_of_bound_binds() {
        let bind = "127.0.0.1:7443".parse().unwrap();
        assert_eq!(
            EgressServiceSpec {
                bind: Some(bind),
                binds: Some(vec![bind]),
                ..EgressServiceSpec::default()
            }
            .validate(),
            Err("EgressService bind and binds are mutually exclusive")
        );
        assert_eq!(
            EgressServiceSpec {
                binds: Some(vec![bind, bind]),
                ..EgressServiceSpec::default()
            }
            .validate(),
            Err("EgressService bind list is invalid")
        );
        assert_eq!(
            EgressServiceSpec {
                binds: Some(
                    (0..33)
                        .map(|port| SocketAddr::from(([127, 0, 0, 1], 7000 + port)))
                        .collect()
                ),
                ..EgressServiceSpec::default()
            }
            .validate(),
            Err("EgressService bind list is invalid")
        );
    }
}

//! Typed control-plane views for listener inventory and system-proxy status.
//!
//! These views deliberately do not own listener lifetimes or perform platform
//! mutations. Runtime owners publish them to the local/API adapters.

use std::net::SocketAddr;

use thiserror::Error;

use crate::{ListenerDescriptor, ListenerId, ListenerKind, ProcessMetadataRequest};

/// Runtime availability reported for one configured listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerViewState {
    Available,
    Degraded,
    Unavailable,
}

/// A typed, redaction-safe listener resource view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerView {
    pub id: ListenerId,
    pub kind: ListenerKind,
    pub bind: Option<SocketAddr>,
    pub interface: Option<String>,
    pub address: Option<String>,
    pub mtu: Option<u32>,
    pub flow_tags: std::collections::BTreeSet<String>,
    pub process_metadata: ProcessMetadataRequest,
    pub allowed_sources: Vec<String>,
    pub authentication_required: bool,
    pub state: ListenerViewState,
    pub generation: u64,
    pub status_reason: Option<String>,
}

impl ListenerView {
    #[must_use]
    pub fn from_descriptor(descriptor: &ListenerDescriptor, generation: u64) -> Self {
        Self {
            id: descriptor.id.clone(),
            kind: descriptor.kind,
            bind: descriptor.bind,
            interface: descriptor.interface.clone(),
            address: descriptor.address.clone(),
            mtu: descriptor.mtu,
            flow_tags: descriptor.flow_tags.clone(),
            process_metadata: descriptor.process_metadata,
            allowed_sources: descriptor.allowed_sources.clone(),
            authentication_required: descriptor.authentication_required,
            state: ListenerViewState::Available,
            generation,
            status_reason: None,
        }
    }

    #[must_use]
    pub const fn supports_system_proxy(&self) -> bool {
        matches!(
            self.kind,
            ListenerKind::Http | ListenerKind::Socks5 | ListenerKind::Mixed
        )
    }
}

/// A point-in-time inventory returned by control-plane listener queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerInventory {
    pub generation: u64,
    pub listeners: Vec<ListenerView>,
}

impl ListenerInventory {
    #[must_use]
    pub fn from_descriptors<'a, I>(generation: u64, descriptors: I) -> Self
    where
        I: IntoIterator<Item = &'a ListenerDescriptor>,
    {
        Self {
            generation,
            listeners: descriptors
                .into_iter()
                .map(|descriptor| ListenerView::from_descriptor(descriptor, generation))
                .collect(),
        }
    }

    #[must_use]
    pub fn get(&self, id: &ListenerId) -> Option<&ListenerView> {
        self.listeners.iter().find(|listener| listener.id == *id)
    }

    pub fn select_system_proxy_listener(
        &self,
        id: &ListenerId,
    ) -> Result<&ListenerView, ListenerSelectionError> {
        let listener = self
            .get(id)
            .ok_or_else(|| ListenerSelectionError::NotFound { id: id.clone() })?;
        if !listener.supports_system_proxy() {
            return Err(ListenerSelectionError::IncompatibleKind {
                id: id.clone(),
                kind: listener.kind,
            });
        }
        Ok(listener)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ListenerSelectionError {
    #[error("listener {id:?} was not found")]
    NotFound { id: ListenerId },
    #[error("listener {id:?} of kind {kind:?} cannot back system proxy")]
    IncompatibleKind { id: ListenerId, kind: ListenerKind },
}

/// Platform effect of the Windows system-proxy control-plane switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemProxyPlatformEffect {
    Disabled,
    Applied,
    Unsupported,
    Failed,
}

/// Restoration status for values captured before system-proxy activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemProxyRestorationState {
    NotRequired,
    Pending,
    Restored,
    Failed,
}

/// Typed status returned by `GET /api/v1/system-proxy` and its change events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemProxyStatusView {
    pub enabled: bool,
    pub listener_id: Option<ListenerId>,
    pub platform_effect: SystemProxyPlatformEffect,
    pub environment_applied: bool,
    pub operating_system_applied: bool,
    pub restoration_state: SystemProxyRestorationState,
    pub error: Option<String>,
}

impl Default for SystemProxyStatusView {
    fn default() -> Self {
        Self {
            enabled: false,
            listener_id: None,
            platform_effect: SystemProxyPlatformEffect::Disabled,
            environment_applied: false,
            operating_system_applied: false,
            restoration_state: SystemProxyRestorationState::NotRequired,
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn descriptor(id: &str, kind: ListenerKind) -> ListenerDescriptor {
        ListenerDescriptor {
            id: ListenerId::new(id),
            kind,
            bind: Some(SocketAddr::from_str("127.0.0.1:8080").expect("socket address")),
            interface: None,
            address: None,
            mtu: None,
            flow_tags: std::collections::BTreeSet::new(),
            process_metadata: crate::ProcessMetadataRequest::default(),
            allowed_sources: vec!["127.0.0.1/32".to_owned()],
            authentication_required: false,
        }
    }

    #[test]
    fn inventory_preserves_typed_listener_fields_and_generation() {
        let http = descriptor("local-http", ListenerKind::Http);
        let inventory = ListenerInventory::from_descriptors(7, [&http]);

        assert_eq!(inventory.generation, 7);
        let view = inventory
            .get(&ListenerId::new("local-http"))
            .expect("listener");
        assert_eq!(view.kind, ListenerKind::Http);
        assert_eq!(view.allowed_sources, vec!["127.0.0.1/32"]);
        assert!(view.flow_tags.is_empty());
        assert_eq!(view.state, ListenerViewState::Available);
        assert!(view.supports_system_proxy());
    }

    #[test]
    fn system_proxy_selection_rejects_unknown_and_non_proxy_listeners() {
        let tun = descriptor("lan-tun", ListenerKind::Tun);
        let inventory = ListenerInventory::from_descriptors(1, [&tun]);

        assert!(matches!(
            inventory.select_system_proxy_listener(&ListenerId::new("missing")),
            Err(ListenerSelectionError::NotFound { .. })
        ));
        assert!(matches!(
            inventory.select_system_proxy_listener(&ListenerId::new("lan-tun")),
            Err(ListenerSelectionError::IncompatibleKind {
                kind: ListenerKind::Tun,
                ..
            })
        ));
    }

    #[test]
    fn mixed_listener_is_available_for_system_proxy_selection() {
        let mixed = descriptor("shared-proxy", ListenerKind::Mixed);
        let inventory = ListenerInventory::from_descriptors(9, [&mixed]);
        let selected = inventory
            .select_system_proxy_listener(&mixed.id)
            .expect("mixed listener");
        assert_eq!(selected.kind, ListenerKind::Mixed);
        assert_eq!(selected.bind, mixed.bind);
        assert_eq!(selected.generation, 9);
    }

    #[test]
    fn system_proxy_status_defaults_to_disabled_without_platform_side_effects() {
        let status = SystemProxyStatusView::default();

        assert!(!status.enabled);
        assert_eq!(status.listener_id, None);
        assert_eq!(status.platform_effect, SystemProxyPlatformEffect::Disabled);
        assert!(!status.environment_applied);
        assert!(!status.operating_system_applied);
        assert_eq!(
            status.restoration_state,
            SystemProxyRestorationState::NotRequired
        );
        assert_eq!(status.error, None);
    }
}

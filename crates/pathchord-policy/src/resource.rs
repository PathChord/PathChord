/// The owning configuration identity, separate from wire identities and opaque
/// credential references. Resource kind is carried by the typed ID/collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceIdentity<'a> {
    pub namespace: &'a str,
    pub name: &'a str,
}

impl<'a> ResourceIdentity<'a> {
    pub const DEFAULT_NAMESPACE: &'static str = "default";
    pub const MAX_INTERNAL_ID_BYTES: usize = 255;
    const MAX_RESOURCE_NAME_BYTES: usize = 63;

    /// Decode an internal resource ID. The length prefix makes namespace/name
    /// boundaries unambiguous even for namespaces containing separators.
    pub fn from_id(id: &'a str) -> Self {
        let qualified = id.strip_prefix('@').and_then(|value| {
            let (length, tail) = value.split_once(':')?;
            let length = length.parse::<usize>().ok()?;
            if !tail.is_char_boundary(length) {
                return None;
            }
            let namespace = tail.get(..length)?;
            let name = tail.get(length..)?.strip_prefix('/')?;
            Some(Self { namespace, name })
        });
        qualified.unwrap_or(Self {
            namespace: Self::DEFAULT_NAMESPACE,
            name: id,
        })
    }

    pub fn into_id(self) -> String {
        if self.namespace == Self::DEFAULT_NAMESPACE {
            self.name.to_owned()
        } else {
            format!("@{}:{}/{}", self.namespace.len(), self.namespace, self.name)
        }
    }

    /// Reserve space for any valid resource or imported node name in this
    /// namespace, including names generated after a Subscription refresh.
    pub fn is_representable(self) -> bool {
        let name_bytes = self.name.len().max(Self::MAX_RESOURCE_NAME_BYTES);
        let encoded_bytes = if self.namespace == Self::DEFAULT_NAMESPACE {
            name_bytes
        } else {
            self.namespace
                .len()
                .saturating_add(self.namespace.len().to_string().len())
                .saturating_add(3)
                .saturating_add(name_bytes)
        };
        encoded_bytes <= Self::MAX_INTERNAL_ID_BYTES
    }

    /// A single safe filesystem component for owner journals. Preserve existing
    /// default-namespace resource filenames so crash recovery can still find
    /// them; the reserved prefix cannot be an authored resource name.
    pub fn storage_component(self) -> String {
        if self.namespace == Self::DEFAULT_NAMESPACE
            && !self.name.is_empty()
            && self.name.len() <= Self::MAX_RESOURCE_NAME_BYTES
            && self
                .name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            self.name.to_owned()
        } else {
            use std::fmt::Write as _;
            let digest =
                orion::hazardous::hash::sha2::sha256::Sha256::digest(self.into_id().as_bytes())
                    .expect("bounded resource identity fits SHA-256");
            let mut component = String::with_capacity(65);
            component.push('_');
            for byte in digest.as_ref() {
                write!(component, "{byte:02x}").expect("writing to a String cannot fail");
            }
            component
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_preserve_namespaces_and_canonical_names_without_collisions() {
        for namespace in ["default", "team-a", "team/b", "ns:with/separators", "中文"] {
            let identity = ResourceIdentity {
                namespace,
                name: "edge",
            };
            let id = identity.into_id();
            assert_eq!(ResourceIdentity::from_id(&id), identity);
            if namespace != "default" {
                assert_ne!(id, "edge");
            }
        }
        assert_ne!(
            ResourceIdentity {
                namespace: "a/b",
                name: "c"
            }
            .into_id(),
            ResourceIdentity {
                namespace: "a",
                name: "b/c"
            }
            .into_id(),
        );
    }

    #[test]
    fn owner_journal_components_are_distinct_safe_and_preserve_legacy_names() {
        let mut components = std::collections::BTreeSet::new();
        for namespace in ["default", "tenant-a", "tenant/a", "tenant_a", "租户"] {
            let identity = ResourceIdentity {
                namespace,
                name: "tproxy",
            };
            let component = identity.storage_component();
            assert!(!component.contains(['/', '\\', ':']));
            assert!(components.insert(component.clone()));
            if namespace == "default" {
                assert_eq!(component, "tproxy");
            }
        }
        let namespace = "n".repeat(127);
        let name = "a".repeat(63);
        let identity = ResourceIdentity {
            namespace: &namespace,
            name: &name,
        };
        assert!(identity.is_representable());
        assert_eq!(identity.storage_component().len(), 65);
        assert!(format!("{}-routing.json", identity.storage_component()).len() <= 255);
        for length in [64, 255] {
            let name = "a".repeat(length);
            let component = ResourceIdentity {
                namespace: "default",
                name: &name,
            }
            .storage_component();
            assert_eq!(component.len(), 65);
            assert!(format!("{component}-routing.json").len() <= 255);
        }
    }

    #[test]
    fn namespace_capacity_reserves_a_full_generated_resource_name() {
        for (length, accepted) in [(127, true), (186, true), (187, false), (255, false)] {
            let namespace = "n".repeat(length);
            assert_eq!(
                ResourceIdentity {
                    namespace: &namespace,
                    name: "x"
                }
                .is_representable(),
                accepted
            );
        }
        assert!(
            !ResourceIdentity {
                namespace: "default",
                name: &"x".repeat(256)
            }
            .is_representable()
        );
    }
}

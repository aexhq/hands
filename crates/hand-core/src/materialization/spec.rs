//! Target identity and the immutable per-generation spec.

use super::*;

/// A logical target within one root session tree.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TargetKey {
    pub root_id: String,
    /// `target:default` or `target:additional:<sandbox_id>`.
    pub target_key: String,
}

impl TargetKey {
    pub fn default(root_id: impl Into<String>) -> Result<Self, MaterializationError> {
        let root_id = root_id.into();
        validate_identifier(&root_id, "root_id")?;
        Ok(Self {
            root_id,
            target_key: DEFAULT_TARGET_KEY.into(),
        })
    }

    pub fn additional(
        root_id: impl Into<String>,
        sandbox_id: impl Into<String>,
    ) -> Result<Self, MaterializationError> {
        let root_id = root_id.into();
        let sandbox_id = sandbox_id.into();
        validate_identifier(&root_id, "root_id")?;
        validate_identifier(&sandbox_id, "sandbox_id")?;
        Ok(Self {
            root_id,
            target_key: format!("target:additional:{sandbox_id}"),
        })
    }

    #[must_use]
    pub fn is_default(&self) -> bool {
        self.target_key == DEFAULT_TARGET_KEY
    }

    pub fn validate(&self) -> Result<(), MaterializationError> {
        validate_identifier(&self.root_id, "root_id")?;
        if self.is_default() {
            return Ok(());
        }
        validate_identifier(self.sandbox_identity()?, "sandbox_id")
    }

    /// Sandbox identity for capability minting and status projection: `"default"` for the
    /// default target, the sandbox id for additional targets. Fails on any other key shape
    /// instead of guessing.
    pub fn sandbox_identity(&self) -> Result<&str, MaterializationError> {
        if self.is_default() {
            return Ok("default");
        }
        self.target_key
            .strip_prefix("target:additional:")
            .ok_or(MaterializationError::InvalidIdentity("target_key"))
    }
}

/// Everything that must remain immutable for one physical generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetSpec {
    pub connector: ConnectorClass,
    /// Immutable image digest/version identity resolved by the trusted Hand process.
    pub image_identity: String,
    /// Plane-owned physical size/class. Tenant input never becomes a provider identifier.
    pub resource_class: String,
    /// Physical provider memory charged against the account/region materialization quota.
    pub materialized_mib: u64,
    /// Digest of the exact execution-resource ceiling sealed for this generation.
    pub resource_policy_digest: String,
    /// Digest of the exact network ceiling sealed for this generation. Connector class alone is
    /// insufficient because two allowlists can name different destinations.
    pub network_policy_digest: String,
}

impl TargetSpec {
    pub fn new(
        connector: ConnectorClass,
        image_identity: impl Into<String>,
        resource_class: impl Into<String>,
        materialized_mib: u64,
        resource_policy_digest: impl Into<String>,
        network_policy_digest: impl Into<String>,
    ) -> Result<Self, MaterializationError> {
        let image_identity = image_identity.into();
        let resource_class = resource_class.into();
        let resource_policy_digest = resource_policy_digest.into();
        let network_policy_digest = network_policy_digest.into();
        validate_bounded_token(&image_identity, "image_identity", 256)?;
        validate_identifier(&resource_class, "resource_class")?;
        if materialized_mib == 0 || materialized_mib > 1_048_576 {
            return Err(MaterializationError::InvalidCapacity);
        }
        validate_digest(&resource_policy_digest, "resource_policy_digest")?;
        validate_digest(&network_policy_digest, "network_policy_digest")?;
        Ok(Self {
            connector,
            image_identity,
            resource_class,
            materialized_mib,
            resource_policy_digest,
            network_policy_digest,
        })
    }

    /// Stable digest used by storage CAS expressions. This is an internal identity, not a fork of
    /// Brain's public contract digest. Canonical JSON (JCS) keeps the digest independent of
    /// struct field order.
    #[must_use]
    pub fn digest(&self) -> String {
        let encoded = serde_jcs::to_vec(self).expect("TargetSpec serialization is infallible");
        hex::encode(Sha256::digest(encoded))
    }
}

//! Environment-derived plane configuration.

use crate::*;

#[derive(Debug, Clone)]
pub struct HandPlaneConfig {
    pub region: String,
    pub image: String,
    pub image_version: String,
    pub registry_table: String,
    pub max_materialized_mib: u64,
    pub bundle_cache_max_bytes: usize,
    pub bundle_fetch_max_bytes: usize,
    pub connectors: ConnectorCatalog,
    pub capability_signing_key_id: String,
    pub egress_gateway_authority: GatewayAuthority,
}

impl HandPlaneConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let required = |name: &str| -> anyhow::Result<String> {
            let value = std::env::var(name)
                .map_err(|_| anyhow::anyhow!("{name} is required for the production Hand"))?;
            anyhow::ensure!(!value.trim().is_empty(), "{name} cannot be empty");
            Ok(value)
        };
        let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".into());
        anyhow::ensure!(
            region == "us-east-1",
            "the MVP Hand plane is pinned to us-east-1"
        );
        let connectors = ConnectorCatalog::from_lookup(|class| {
            let name = match class {
                ConnectorClass::None => "HAND_NETWORK_CONNECTOR_NONE",
                ConnectorClass::Allowlist => "HAND_NETWORK_CONNECTOR_ALLOWLIST",
                ConnectorClass::Public => "HAND_NETWORK_CONNECTOR_PUBLIC",
            };
            std::env::var(name).ok()
        })?;
        for class in [
            ConnectorClass::None,
            ConnectorClass::Allowlist,
            ConnectorClass::Public,
        ] {
            hand_lambda::image::validate_network_connector_arn(
                connectors.resolve(class).as_str(),
                &region,
            )?;
        }
        let max_materialized_mib: u64 = required("HAND_MAX_MATERIALIZED_MIB")?.parse()?;
        anyhow::ensure!(
            max_materialized_mib >= TARGET_MEMORY_MIB
                && max_materialized_mib.is_multiple_of(TARGET_MEMORY_MIB),
            "HAND_MAX_MATERIALIZED_MIB must be a positive multiple of 1024"
        );
        let bundle_cache_max_mib = optional_mib(
            "HAND_BUNDLE_CACHE_MAX_MIB",
            DEFAULT_BUNDLE_CACHE_MAX_MIB,
            16,
            MAX_CONFIGURED_BUNDLE_CACHE_MIB,
        )?;
        let bundle_fetch_max_mib = optional_mib(
            "HAND_BUNDLE_FETCH_MAX_MIB",
            DEFAULT_BUNDLE_FETCH_MAX_MIB,
            16,
            bundle_cache_max_mib,
        )?;
        Ok(Self {
            region,
            image: required("HAND_IMAGE")?,
            image_version: required("HAND_IMAGE_VERSION")?,
            registry_table: required("HAND_REGISTRY_TABLE")?,
            max_materialized_mib,
            bundle_cache_max_bytes: mib_bytes(bundle_cache_max_mib)?,
            bundle_fetch_max_bytes: mib_bytes(bundle_fetch_max_mib)?,
            connectors,
            capability_signing_key_id: required("HAND_CAPABILITY_SIGNING_KEY_ID")?,
            egress_gateway_authority: GatewayAuthority::parse(&required(
                "HAND_EGRESS_GATEWAY_AUTHORITY",
            )?)?,
        })
    }
}

pub(crate) fn optional_mib(name: &str, default: u64, min: u64, max: u64) -> anyhow::Result<u64> {
    let value = match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("{name} must be an integer number of MiB"))?,
        Err(std::env::VarError::NotPresent) => default,
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{name} must be valid UTF-8")
        }
    };
    anyhow::ensure!(
        (min..=max).contains(&value),
        "{name} must be between {min} and {max} MiB"
    );
    Ok(value)
}

pub(crate) fn mib_bytes(value: u64) -> anyhow::Result<usize> {
    usize::try_from(
        value
            .checked_mul(MIB as u64)
            .ok_or_else(|| anyhow::anyhow!("bundle memory bound overflows"))?,
    )
    .map_err(|_| anyhow::anyhow!("bundle memory bound does not fit this process"))
}

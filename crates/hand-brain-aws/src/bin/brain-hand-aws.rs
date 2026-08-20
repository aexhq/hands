//! Hosted Brain composition: neutral AWS journal/custody plus the Lambda MicroVM Hand.
//!
//! A downstream product supplies only process configuration and an optional generic server-Tool
//! executor. There are no Aex names, output rules, account concepts, or billing behavior here.

use std::sync::Arc;

use brain::api::{AppState, serve};
use brain::session::BrainConfig;
use brain_aws::AwsPersistenceConfig;
use hand_brain_aws::LambdaFactory;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "brain=info,brain_aws=info,hand_brain_aws=info".into()),
        )
        .init();

    let token = required("BRAIN_API_TOKEN")?;
    let address = std::env::var("BRAIN_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8700".into())
        .parse()?;
    let config = BrainConfig::default();
    validate_executor_config(&config)?;
    let persistence = AwsPersistenceConfig::from_env().map_err(|error| anyhow::anyhow!(error))?;
    let hands = Arc::new(
        LambdaFactory::from_env()
            .await
            .map_err(|error| anyhow::anyhow!(error))?,
    );
    hands
        .verify()
        .await
        .map_err(|error| anyhow::anyhow!(error))?;
    let brain = brain_aws::compose(config, persistence, hands, None)
        .await
        .map_err(|error| anyhow::anyhow!(error))?;
    serve(AppState { brain, token }, address).await
}

fn required(name: &str) -> anyhow::Result<String> {
    let value = std::env::var(name).map_err(|_| anyhow::anyhow!("{name} is not set"))?;
    if value.trim().is_empty() {
        anyhow::bail!("{name} cannot be empty");
    }
    Ok(value)
}

fn validate_executor_config(config: &BrainConfig) -> anyhow::Result<()> {
    match (
        &config.external_executor_url,
        &config.external_executor_token,
    ) {
        (None, None) if config.external_executor_capabilities.is_empty() => Ok(()),
        (Some(url), Some(_)) if !config.external_executor_capabilities.is_empty() => {
            let parsed = reqwest::Url::parse(url)
                .map_err(|error| anyhow::anyhow!("BRAIN_EXTERNAL_TOOL_EXECUTOR_URL: {error}"))?;
            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                anyhow::bail!("BRAIN_EXTERNAL_TOOL_EXECUTOR_URL must use HTTP or HTTPS");
            }
            Ok(())
        }
        _ => anyhow::bail!(
            "BRAIN_EXTERNAL_TOOL_EXECUTOR_URL, BRAIN_EXTERNAL_TOOL_EXECUTOR_TOKEN, and BRAIN_EXTERNAL_TOOL_CAPABILITIES must be configured together"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executor_configuration_is_all_or_nothing() {
        let mut config = BrainConfig {
            external_executor_url: None,
            external_executor_token: None,
            external_executor_capabilities: Default::default(),
            ..BrainConfig::default()
        };
        assert!(validate_executor_config(&config).is_ok());
        config.external_executor_url = Some("http://127.0.0.1:8601/call".into());
        assert!(validate_executor_config(&config).is_err());
        config.external_executor_token = Some(brain::config::ProviderKey::new("secret"));
        config
            .external_executor_capabilities
            .insert("finish.v1".into());
        assert!(validate_executor_config(&config).is_ok());
        config.external_executor_url = Some("file:///tmp/call".into());
        assert!(validate_executor_config(&config).is_err());
    }
}

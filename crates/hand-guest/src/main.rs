//! `hand-guest` binary: read config from the environment, serve the ABI until killed.

use std::sync::Arc;

use hand_guest::{Config, Hand, Server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("hand_guest=info".parse()?),
        )
        .with_target(false)
        .init();
    let cfg = Config::from_env()?;
    let hand: Arc<Hand> = Hand::new(cfg)?;
    let server = Server::bind(hand.clone()).await?;
    let serve = tokio::spawn(server.run());
    tokio::select! {
        r = serve => { r??; }
        _ = shutdown_signal() => {
            tracing::info!("shutting down: cancelling operations");
            hand.shutdown().await;
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
    tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
}

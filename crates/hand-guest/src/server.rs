//! One port, three kinds of traffic (axum):
//!
//! - `GET /` with a WebSocket upgrade → the ABI: JSON text frames, requests multiplexed by id.
//! - `GET /` plain → a probe: identity and lifecycle phase, no secrets. Through the provider's
//!   authenticated endpoint this doubles as the speculative resume trigger — an endpoint
//!   request to a suspended MicroVM is held until `/resume` completes.
//! - `POST /aws/lambda-microvms/runtime/v1/{run,resume,suspend,terminate,ready,validate}` →
//!   the provider lifecycle hooks ([`crate::hooks`]).
//!
//! One port is deliberate: the MicroVM endpoint auth token is scoped to a single port, and a
//! second unauthenticated port would be a hole, not a feature.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Json};
use axum::routing::{get, post};
use brain_protocol::abi::{HandFrame, Request, RequestId, Response, ResponseResult};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::config::MAX_FRAME_BYTES;
use crate::errors::malformed;
use crate::hand::{Hand, is_fatal_for_connection};
use crate::hooks;

pub struct Server {
    listener: TcpListener,
    hand: Arc<Hand>,
}

impl Server {
    pub async fn bind(hand: Arc<Hand>) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(hand.cfg.listen).await?;
        Ok(Self { listener, hand })
    }

    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub async fn run(self) -> anyhow::Result<()> {
        tracing::info!(
            addr = %self.local_addr()?,
            generation = %*self.hand.generation_id,
            armed = self.hand.armed(),
            "hand listening"
        );
        let hooks = Router::new()
            .route("/run", post(hooks::run))
            .route("/resume", post(hooks::resume))
            .route("/suspend", post(hooks::suspend))
            .route("/terminate", post(hooks::terminate))
            .route("/ready", post(hooks::ready))
            .route("/validate", post(hooks::validate));
        let app = Router::new()
            .route("/", get(root))
            .nest(hooks::HOOK_PREFIX, hooks)
            .with_state(self.hand);
        // TCP_NODELAY: ABI frames are small; Nagle plus delayed ACK added a measured ~40 ms
        // to every operation round trip.
        use axum::serve::ListenerExt as _;
        let listener = self.listener.tap_io(|io| {
            let _ = io.set_nodelay(true);
        });
        axum::serve(listener, app).await?;
        Ok(())
    }
}

/// An optional WebSocket upgrade. axum 0.8 does not implement the optional extractor for
/// `WebSocketUpgrade`, so this wrapper turns "not an upgrade request" into `None` instead of a
/// rejection — letting one `GET /` serve both the ABI socket and the plain probe.
struct MaybeWs(Option<WebSocketUpgrade>);

impl<S: Send + Sync> FromRequestParts<S> for MaybeWs {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(MaybeWs(
            WebSocketUpgrade::from_request_parts(parts, state)
                .await
                .ok(),
        ))
    }
}

/// `GET /`: the ABI WebSocket when the client upgrades, the probe document when it does not.
async fn root(State(hand): State<Arc<Hand>>, MaybeWs(ws): MaybeWs) -> axum::response::Response {
    match ws {
        Some(upgrade) => upgrade
            .max_message_size(MAX_FRAME_BYTES as usize)
            .max_frame_size(MAX_FRAME_BYTES as usize)
            .on_upgrade(move |socket| async move {
                if let Err(e) = serve_connection(hand, socket).await {
                    tracing::warn!(error = %e, "connection ended with error");
                }
            }),
        None => Json(serde_json::json!({
            "service": "hand",
            "abi_major": brain_protocol::abi::ProtocolVersion::CURRENT.major,
            "generation_id": hand.generation_id.to_string(),
            "boot_id": hand.boot_id.to_string(),
            "armed": hand.armed(),
            "lifecycle": *hand.lifecycle.read().unwrap(),
        }))
        .into_response(),
    }
}

async fn serve_connection(hand: Arc<Hand>, ws: WebSocket) -> anyhow::Result<()> {
    let (mut sink, mut source) = ws.split();
    let (tx, mut rx) = mpsc::channel::<HandFrame>(256);

    // Writer: everything hand -> brain goes through here.
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            let text = match serde_json::to_string(&frame) {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(error = %e, "serialising frame");
                    continue;
                }
            };
            if sink.send(Message::Text(text.into())).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    // Status forwarder: broadcast -> this connection.
    let mut status_rx = hand.status.subscribe();
    let tx_status = tx.clone();
    let forwarder = tokio::spawn(async move {
        loop {
            match status_rx.recv().await {
                Ok(ev) => {
                    if tx_status.send(HandFrame::HandStatus(ev)).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
    });

    let (fatal_tx, mut fatal_rx) = mpsc::channel::<()>(1);
    loop {
        let msg = tokio::select! {
            m = source.next() => m,
            _ = fatal_rx.recv() => break,
        };
        let Some(msg) = msg else { break };
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(error = %e, "ws read");
                break;
            }
        };
        let text = match msg {
            Message::Text(t) => t.to_string(),
            Message::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => break,
        };
        let hand = hand.clone();
        let tx = tx.clone();
        let fatal_tx = fatal_tx.clone();
        tokio::spawn(async move {
            let (id, result) = match serde_json::from_str::<Request>(&text) {
                Ok(req) => {
                    let id = req.id.clone();
                    (Some(id), hand.handle(req).await)
                }
                Err(e) => (
                    None,
                    ResponseResult::Error {
                        error: malformed(format!("request: {e}")),
                    },
                ),
            };
            let fatal = matches!(&result, ResponseResult::Error { error } if is_fatal_for_connection(error));
            // A request we could not even parse has no id to answer to; use a placeholder so the
            // brain still sees the refusal.
            let id: RequestId = id.unwrap_or_else(|| "unparseable".parse().expect("id"));
            let _ = tx.send(HandFrame::Response(Response { id, result })).await;
            if fatal {
                let _ = fatal_tx.send(()).await;
            }
        });
    }
    drop(tx);
    forwarder.abort();
    let _ = writer.await;
    Ok(())
}

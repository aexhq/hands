//! WebSocket transport: one connection per brain, JSON text frames, requests multiplexed by id.
//! Each request runs as its own task; responses and `hand_status` events share one writer.

use std::net::SocketAddr;
use std::sync::Arc;

use aex_contracts::abi::{HandFrame, Request, RequestId, Response, ResponseResult};
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::config::MAX_FRAME_BYTES;
use crate::errors::malformed;
use crate::hand::{Hand, is_fatal_for_connection};

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
        tracing::info!(addr = %self.local_addr()?, generation = %*self.hand.generation_id, "hand listening");
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let hand = self.hand.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_connection(hand, stream).await {
                    tracing::warn!(%peer, error = %e, "connection ended with error");
                }
            });
        }
    }
}

async fn serve_connection(hand: Arc<Hand>, stream: TcpStream) -> anyhow::Result<()> {
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME_BYTES as usize))
        .max_frame_size(Some(MAX_FRAME_BYTES as usize));
    let ws = tokio_tungstenite::accept_async_with_config(stream, Some(config)).await?;
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
            Message::Frame(_) => continue,
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

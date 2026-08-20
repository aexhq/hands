//! Drive one real Hand session over WebSocket. This is a consumer of Brain's client crate, not
//! a second protocol implementation.

use std::time::Duration;

use base64::Engine;
use brain_hand_client::{HandClient, root_lane, start_request};
use brain_protocol::abi::{
    CancelRequest, Cursor, HelloRequest, LaneMode, LaneRef, OperationStatus, PollRequest,
    ProtocolVersion, Stream, SyncScope,
};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let url = args.next().unwrap_or_else(|| "ws://127.0.0.1:8080/".into());
    let token = args.next().unwrap_or_else(|| "tok".into());

    let client = HandClient::connect(&url, 1).await?;
    let hello = client
        .hello(HelloRequest {
            protocol: ProtocolVersion::CURRENT,
            session_id: "ses_smoke0000000000000000000".parse()?,
            session_token: token,
            expected_generation_id: None,
            tool_manifest: brain_protocol::tools::manifest_v1().clone(),
            tool_manifest_digest: brain_protocol::tools::TOOL_MANIFEST_V1_DIGEST
                .trim()
                .parse()?,
            env: Default::default(),
            sync: SyncScope {
                roots: vec![workspace(), "/home/agent".into()],
                exclude: vec![],
            },
            restore: None,
            heartbeat_ms: 2_000,
        })
        .await?;
    assert_eq!(hello.tools.len(), 7);

    let write = client
        .start(start_request(
            "s-write",
            "write",
            json!({"path": "hello.txt", "content": "hi from the hand\n"}),
            root_lane(),
            None,
            false,
            10_000,
            0,
        ))
        .await?;
    assert_eq!(
        write.view.terminal.as_ref().and_then(|t| t.exit_code),
        Some(0)
    );
    let read = client
        .start(start_request(
            "s-read",
            "read",
            json!({"path": "hello.txt"}),
            root_lane(),
            None,
            false,
            10_000,
            4_096,
        ))
        .await?;
    assert_eq!(decode(&read.slices), "hi from the hand\n");

    let bash = client
        .start(start_request(
            "s-bash",
            "bash",
            json!({"command": "test \"$(node --version)\" = v22.23.2; python3 --version; git --version"}),
            root_lane(),
            None,
            false,
            30_000,
            65_536,
        ))
        .await?;
    assert_eq!(
        bash.view.terminal.as_ref().and_then(|t| t.exit_code),
        Some(0)
    );

    client
        .start(start_request(
            "s-job",
            "bash",
            json!({"command": "for i in $(seq 1 100); do echo tick $i; sleep 0.1; done"}),
            LaneRef {
                id: "L".parse()?,
                mode: LaneMode::Persistent,
                parent: None,
            },
            None,
            true,
            0,
            0,
        ))
        .await?;
    let poll = client
        .poll(PollRequest {
            operation_id: "s-job".parse()?,
            cursors: vec![Cursor {
                stream: Stream::Stdout,
                offset: 0,
            }],
            max_bytes: 4_096,
            wait_ms: 2_000,
        })
        .await?;
    assert!(decode(&poll.slices).starts_with("tick 1\n"));
    assert_eq!(poll.view.status, OperationStatus::Running);
    assert!(
        client
            .cancel(CancelRequest {
                operation_id: "s-job".parse()?,
                grace_ms: Some(500),
            })
            .await?
            .accepted
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    println!("SMOKE PASS");
    Ok(())
}

fn workspace() -> String {
    std::env::var("HAND_WORKSPACE").unwrap_or_else(|_| "/workspace".into())
}

fn decode(slices: &[brain_protocol::abi::OutputSlice]) -> String {
    let mut bytes = Vec::new();
    for slice in slices.iter().filter(|slice| slice.stream == Stream::Stdout) {
        bytes.extend(
            base64::engine::general_purpose::STANDARD
                .decode(slice.data_base64.as_bytes())
                .expect("Hand emitted valid base64"),
        );
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

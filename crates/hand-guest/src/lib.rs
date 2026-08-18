//! aex hand guest agent — serves the brain↔hand ABI v1 (`aex_contracts::abi`) inside the sandbox.
//!
//! One process per hand. It listens for one multiplexed WebSocket per brain connection, keeps
//! lanes (persistent shell environments), runs operations (tool calls) with bounded, spilled
//! output, moves files in/out over presigned URLs, and syncs the workspace as packs + manifests.
//! Semantics: `aex/contracts/abi/v1/README.md`.

pub mod config;
pub mod errors;
pub mod exec;
pub mod hand;
pub mod hooks;
pub mod lanes;
pub mod ops;
pub mod server;
pub mod spill;
pub mod status;
pub mod sync;
pub mod tools;
pub mod transfer;

pub use config::Config;
pub use hand::Hand;
pub use server::Server;

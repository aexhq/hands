//! Default Aex-managed Hand guest.
//!
//! Brain owns the public receipt contract. This crate implements the physical-generation side of
//! that contract: exact request deduplication, bounded terminal retention, immutable target seals,
//! verified Node22 bundles, live files, and explicit additional-sandbox execution. It deliberately
//! contains no workspace checkpoint or implicit persistence path.

mod acks;
pub mod config;
pub mod errors;
mod file_effects;
pub mod hand;
pub mod hooks;
pub mod process;
pub mod server;

pub use config::Config;
pub use hand::Hand;
pub use server::Server;

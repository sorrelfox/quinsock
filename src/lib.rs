//! quinsock: a high-performance SOCKS5 proxy server (RFC 1928, RFC 1929).

pub mod acl;
pub mod auth;
pub mod client;
pub mod config;
pub mod error;
mod handlers;
pub mod net;
pub mod protocol;
mod relay;
pub mod resolver;
pub mod server;
mod session;

pub use config::Config;
pub use server::{Server, ShutdownHandle};

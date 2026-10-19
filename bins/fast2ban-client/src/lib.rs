//! Fast2Ban client library.

pub mod client;
pub mod socket;

pub use client::run_client;
pub use socket::ClientSocket;

//! Import passwords from a macOS Passwords CSV export into `pass` (passwordstore.org).
//!
//! Modules are exposed as a library so that benchmarks (`benches/`) and
//! integration tests can reuse them.

pub mod cli;
pub mod gpg;
pub mod i18n;
pub mod pipeline;
pub mod sanitize;
pub mod store;

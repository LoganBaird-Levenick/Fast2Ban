//! Fail2Ban-compatible configuration reader.
//!
//! Reads an existing Fail2Ban configuration tree (`fail2ban.conf`,
//! `jail.conf`, `jail.d`, `filter.d`, `action.d`, `paths-*.conf`, `*.local`)
//! unmodified and produces the same client command stream as upstream's
//! `fail2ban-client -d`. See `PLAN.md` for the compatibility contract.

pub mod arg;
pub mod configurator;
pub mod definition;
pub mod error;
pub mod fail2ban;
pub mod fs;
pub mod ini;
pub mod jail;
pub mod jails;
mod pyjson;
pub mod pyutil;
pub mod reader;

pub use arg::{Arg, Command, Val};
pub use configurator::{
    CONFIG_PARAMS, ConfigResult, Configurator, read_config, read_filter_stream,
};
pub use error::{ConfigError, Result};
pub use fs::{Fs, RealFs};

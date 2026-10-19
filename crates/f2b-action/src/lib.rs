//! Fail2Ban action execution and tag replacement.

pub mod action;
pub mod actions;
pub mod jail;

pub mod ban_extra;
pub mod observer;
pub mod selfips;

pub use ban_extra::BanExtra;
pub use jail::Jail;
pub use observer::Observer;
pub mod exec;
pub mod tags;

pub use action::CommandAction;
pub use actions::Actions;
pub use exec::{ExecResult, build_shell_cmd, execute_cmd};
pub use tags::{ActionInfo, TagReplacer};

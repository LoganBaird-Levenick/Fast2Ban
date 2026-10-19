//! Fail2Ban action execution and tag replacement.

pub mod action;
pub mod actions;
pub mod jail;

pub use jail::Jail;
pub mod exec;
pub mod tags;

pub use action::CommandAction;
pub use actions::Actions;
pub use exec::{ExecResult, build_shell_cmd, execute_cmd};
pub use tags::{ActionInfo, TagReplacer};

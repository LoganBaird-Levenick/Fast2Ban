//! SQLite database persistence for Fast2Ban (`fail2ban/server/database.py`).

pub mod db;
pub mod schema;

pub use db::Fail2BanDb;
pub use schema::{CURRENT_VERSION, create_all_tables, migrate_db};

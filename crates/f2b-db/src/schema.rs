//! SQLite schema definition, PRAGMAs, and migrations from v1, v2, v3 to v4.

use rusqlite::{Connection, Result};

pub const CURRENT_VERSION: i64 = 4;

pub const PRAGMAS: &str = "\
PRAGMA foreign_keys = ON;
PRAGMA synchronous = OFF;
PRAGMA journal_mode = MEMORY;
PRAGMA temp_store = MEMORY;
";

pub const CREATE_FAIL2BAN_DB: &str = "CREATE TABLE IF NOT EXISTS fail2banDb(version INTEGER);";

pub const CREATE_JAILS: &str = "\
CREATE TABLE IF NOT EXISTS jails(
    name TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS jails_name ON jails(name);
";

pub const CREATE_LOGS: &str = "\
CREATE TABLE IF NOT EXISTS logs(
    jail TEXT NOT NULL,
    path TEXT,
    firstlinemd5 TEXT,
    lastfilepos INTEGER DEFAULT 0,
    FOREIGN KEY(jail) REFERENCES jails(name) ON DELETE CASCADE,
    UNIQUE(jail, path),
    UNIQUE(jail, path, firstlinemd5)
);
CREATE INDEX IF NOT EXISTS logs_path ON logs(path);
CREATE INDEX IF NOT EXISTS logs_jail_path ON logs(jail, path);
";

pub const CREATE_BANS: &str = "\
CREATE TABLE IF NOT EXISTS bans(
    jail TEXT NOT NULL,
    ip TEXT,
    timeofban INTEGER NOT NULL,
    bantime INTEGER NOT NULL,
    bancount INTEGER NOT NULL default 1,
    data JSON,
    FOREIGN KEY(jail) REFERENCES jails(name)
);
CREATE INDEX IF NOT EXISTS bans_jail_timeofban_ip ON bans(jail, timeofban);
CREATE INDEX IF NOT EXISTS bans_jail_ip ON bans(jail, ip);
CREATE INDEX IF NOT EXISTS bans_ip ON bans(ip);
";

pub const CREATE_BIPS: &str = "\
CREATE TABLE IF NOT EXISTS bips(
    ip TEXT NOT NULL,
    jail TEXT NOT NULL,
    timeofban INTEGER NOT NULL,
    bantime INTEGER NOT NULL,
    bancount INTEGER NOT NULL default 1,
    data JSON,
    PRIMARY KEY(ip, jail),
    FOREIGN KEY(jail) REFERENCES jails(name)
);
CREATE INDEX IF NOT EXISTS bips_timeofban ON bips(timeofban);
CREATE INDEX IF NOT EXISTS bips_ip ON bips(ip);
";

pub fn apply_pragmas(conn: &Connection) -> Result<()> {
    conn.execute_batch(PRAGMAS)
}

pub fn create_all_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(CREATE_FAIL2BAN_DB)?;
    conn.execute_batch(CREATE_JAILS)?;
    conn.execute_batch(CREATE_LOGS)?;
    conn.execute_batch(CREATE_BANS)?;
    conn.execute_batch(CREATE_BIPS)?;

    conn.execute(
        "INSERT INTO fail2banDb(version) SELECT ?1 WHERE NOT EXISTS (SELECT 1 FROM fail2banDb LIMIT 1)",
        [CURRENT_VERSION],
    )?;
    Ok(())
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    let mut stmt = conn.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1")?;
    let mut rows = stmt.query([table])?;
    Ok(rows.next()?.is_some())
}

/// Migrates an existing database to `CURRENT_VERSION` (4).
pub fn migrate_db(conn: &mut Connection) -> Result<i64> {
    if !table_exists(conn, "fail2banDb")? {
        create_all_tables(conn)?;
        return Ok(CURRENT_VERSION);
    }

    let version: i64 =
        match conn.query_row("SELECT version FROM fail2banDb LIMIT 1", [], |r| r.get(0)) {
            Ok(v) => v,
            Err(_) => {
                create_all_tables(conn)?;
                return Ok(CURRENT_VERSION);
            }
        };

    if version == CURRENT_VERSION {
        return Ok(CURRENT_VERSION);
    }

    if version > CURRENT_VERSION {
        return Err(rusqlite::Error::InvalidQuery);
    }

    // Migration from v1 to v2: update logs schema for 3-tuple UNIQUE
    if version < 2 && table_exists(conn, "logs")? {
        let tx = conn.transaction()?;
        tx.execute_batch(&format!(
            "CREATE TEMPORARY TABLE logs_temp AS SELECT * FROM logs;\
             DROP TABLE logs;\
             {CREATE_LOGS}\
             INSERT INTO logs SELECT * FROM logs_temp;\
             DROP TABLE logs_temp;\
             UPDATE fail2banDb SET version = 2;"
        ))?;
        tx.commit()?;
    }

    // Migration from v2 to v3: update bans schema with bantime and bancount
    if version < 3 && table_exists(conn, "bans")? {
        let tx = conn.transaction()?;
        tx.execute_batch(&format!(
            "CREATE TEMPORARY TABLE bans_temp AS SELECT jail, ip, timeofban, -2 as bantime, 1 as bancount, data FROM bans;\
             DROP TABLE bans;\
             {CREATE_BANS}\
             INSERT INTO bans SELECT * FROM bans_temp;\
             DROP TABLE bans_temp;"
        ))?;
        tx.commit()?;
    }

    // Migration from v3 to v4: add bips table and backfill from bans
    if version < 4 && !table_exists(conn, "bips")? {
        let tx = conn.transaction()?;
        tx.execute_batch(&format!(
            "{CREATE_BIPS}\
             UPDATE fail2banDb SET version = 4;"
        ))?;
        if table_exists(&tx, "bans")? {
            tx.execute(
                "INSERT OR REPLACE INTO bips(ip, jail, timeofban, bantime, bancount, data) \
                 SELECT ip, jail, timeofban, bantime, bancount, data FROM bans ORDER BY timeofban",
                [],
            )?;
        }
        tx.commit()?;
    }

    let final_version: i64 =
        conn.query_row("SELECT version FROM fail2banDb LIMIT 1", [], |r| r.get(0))?;
    Ok(final_version)
}

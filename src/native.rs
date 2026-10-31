//! Native durable storage and audit boundary. Browser state never uses this module.
use super::*;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{fs, path::Path, time::Duration};

fn private_database(path: &Path) -> Result<Connection> {
    check_database_files(path)?;
    if path.exists() {
        let meta = fs::symlink_metadata(path)?;
        ensure!(
            meta.file_type().is_file(),
            "State must be a regular non-symlink file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                meta.permissions().mode() & 0o077 == 0,
                "State permissions must be private"
            );
        }
    } else {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)?;
    }
    let connection = Connection::open(path)?;
    connection.busy_timeout(Duration::from_secs(2))?;
    connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA max_page_count=16384; PRAGMA wal_autocheckpoint=256; PRAGMA journal_size_limit=8388608; CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS counters (grant_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, sequence INTEGER NOT NULL,last_ms INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS revocations (grant_id TEXT PRIMARY KEY); CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, time_ms INTEGER NOT NULL, allowed INTEGER NOT NULL, reason TEXT NOT NULL, input_sha256 TEXT NOT NULL);")?;
    check_database_files(path)?;
    Ok(connection)
}
fn check_database_files(path: &Path) -> Result<()> {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let path = std::path::PathBuf::from(name);
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                ensure!(
                    meta.file_type().is_file(),
                    "Database sidecar must be regular"
                );
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    ensure!(
                        meta.permissions().mode() & 0o077 == 0,
                        "Database sidecar permissions must be private"
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn append_audit(db: &Connection, now: u64, decision: &Decision, digest: &str) -> Result<()> {
    db.execute(
        "INSERT INTO audit_events(time_ms,allowed,reason,input_sha256) VALUES(?1,?2,?3,?4)",
        params![
            now.min(i64::MAX as u64) as i64,
            decision.allowed,
            decision.reason,
            digest
        ],
    )?;
    db.execute(
        "DELETE FROM audit_events WHERE id <= (SELECT MAX(id)-?1 FROM audit_events)",
        [MAX_AUDIT_EVENTS],
    )?;
    Ok(())
}
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: i64,
    pub time_ms: u64,
    pub allowed: bool,
    pub reason: String,
    pub input_sha256: String,
}
pub fn audit(path: &Path, limit: u32) -> Result<Vec<AuditEvent>> {
    ensure!(path.exists(), "State must exist");
    ensure!((1..=2048).contains(&limit), "Audit limit must be 1..2048");
    let db = private_database(path)?;
    let mut stmt = db.prepare(
        "SELECT id,time_ms,allowed,reason,input_sha256 FROM audit_events ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit], |r| {
        Ok(AuditEvent {
            id: r.get(0)?,
            time_ms: r.get::<_, i64>(1)? as u64,
            allowed: r.get(2)?,
            reason: r.get(3)?,
            input_sha256: r.get(4)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}
pub struct Guard {
    db: Connection,
    policy: Policy,
    authority: VerifyingKey,
}
impl Guard {
    pub fn open(path: &Path, policy: Policy, authority: VerifyingKey) -> Result<Self> {
        policy.validate()?;
        let mut db = private_database(path)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (key, value) in [
            ("policy", hash(&policy)?),
            ("authority", hex::encode(authority.to_bytes())),
        ] {
            let current: Option<String> = tx
                .query_row("SELECT value FROM metadata WHERE key=?1", [key], |r| {
                    r.get(0)
                })
                .optional()?;
            if let Some(current) = current {
                ensure!(
                    current == value,
                    "State is bound to a different policy or authority"
                );
            } else {
                tx.execute(
                    "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                    params![key, value],
                )?;
            }
        }
        tx.commit()?;
        Ok(Self {
            db,
            policy,
            authority,
        })
    }
    pub fn process(&mut self, raw: &[u8], now_ms: u64) -> Decision {
        // An over-budget frame is fingerprinted only through the bounded prefix.
        let digest = hex::encode(Sha256::digest(&raw[..raw.len().min(MAX_INPUT_BYTES + 1)]));
        let decision = if raw.len() > MAX_INPUT_BYTES {
            Decision::deny("input_budget")
        } else if let Ok(envelope) = serde_json::from_slice::<Envelope>(raw) {
            self.authorize(envelope, now_ms, &digest)
                .unwrap_or_else(|_| Decision::deny("state_unavailable"))
        } else {
            Decision::deny("invalid_schema")
        };
        if !decision.allowed {
            let audit_result = (|| -> Result<()> {
                let tx = self
                    .db
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                append_audit(&tx, now_ms, &decision, &digest)?;
                tx.commit()?;
                Ok(())
            })();
            if audit_result.is_err() {
                return Decision::deny("state_unavailable");
            }
        }
        decision
    }
    fn authorize(&mut self, envelope: Envelope, now: u64, digest: &str) -> Result<Decision> {
        let verified = match verify_request(&self.policy, &self.authority, envelope, now) {
            Ok(verified) => verified,
            Err(reason) => return Ok(Decision::deny(reason)),
        };
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let revoked: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM revocations WHERE grant_id=?1)",
            [&verified.grant_id],
            |r| r.get(0),
        )?;
        let previous: Option<(String, i64, i64)> = tx
            .query_row(
                "SELECT fingerprint,sequence,last_ms FROM counters WHERE grant_id=?1",
                [&verified.grant_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let previous = previous.map(|(fingerprint, sequence, last_ms)| Admission {
            fingerprint,
            sequence: sequence as u64,
            last_ms: last_ms as u64,
        });
        let count: i64 = if previous.is_none() {
            tx.query_row("SELECT COUNT(*) FROM counters", [], |r| r.get(0))?
        } else {
            0
        };
        if let Some(denial) = admission_denial(
            &self.policy,
            &verified,
            previous.as_ref(),
            revoked,
            count as usize,
            now,
        ) {
            return Ok(denial);
        }
        tx.execute("INSERT INTO counters(grant_id,fingerprint,sequence,last_ms) VALUES(?1,?2,?3,?4) ON CONFLICT(grant_id) DO UPDATE SET sequence=excluded.sequence,last_ms=excluded.last_ms",params![verified.grant_id,verified.fingerprint,verified.sequence as i64,now as i64])?;
        append_audit(&tx, now, &verified.decision, digest)?;
        tx.commit()?;
        // Persist authorization before exposing output: crash between commit and
        // publication is uncertain delivery, never an excuse to replay a command.
        Ok(verified.decision)
    }
}
pub fn revoke(path: &Path, grant_id: &str) -> Result<()> {
    ensure!(identifier(grant_id), "Invalid grant ID");
    ensure!(path.exists(), "State must exist before revocation");
    let mut db = private_database(path)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM revocations WHERE grant_id=?1)",
        [grant_id],
        |r| r.get(0),
    )?;
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM revocations", [], |r| r.get(0))?;
    ensure!(
        exists || count < MAX_REVOCATIONS,
        "Revocation budget exhausted"
    );
    tx.execute(
        "INSERT OR IGNORE INTO revocations(grant_id) VALUES(?1)",
        [grant_id],
    )?;
    tx.commit()?;
    Ok(())
}

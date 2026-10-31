#![forbid(unsafe_code)]
//! Signed capabilities and bounded command/data policy, not a safety-rated controller.
use anyhow::{anyhow, ensure, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path, time::Duration};

pub const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_GRANTS: i64 = 4096;
const MAX_REVOCATIONS: i64 = 4096;
const MAX_AUDIT_EVENTS: i64 = 2048;
const GRANT_DOMAIN: &[u8] = b"robot-cyber-shield/grant/v1\0";
const REQUEST_DOMAIN: &[u8] = b"robot-cyber-shield/request/v1\0";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema: String,
    pub robot_id: String,
    pub session_id: String,
    pub command_principal: String,
    pub telemetry_principal: String,
    pub max_linear_mps: f64,
    pub max_angular_rps: f64,
    pub max_request_age_ms: u64,
    pub max_grant_ttl_ms: u64,
    pub min_command_interval_ms: u64,
    pub command_lease_ms: u64,
    pub position_grid_m: f64,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Command,
    Telemetry,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub schema: String,
    pub grant_id: String,
    pub robot_id: String,
    pub session_id: String,
    pub principal: String,
    pub holder_public_key: String,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
    pub capabilities: Vec<Capability>,
    pub max_linear_mps: f64,
    pub max_angular_rps: f64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub claims: Claims,
    pub signature: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRequest {
    pub robot_id: String,
    pub session_id: String,
    pub principal: String,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub linear_mps: f64,
    pub angular_rps: f64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Idle,
    Moving,
    Fault,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryRequest {
    pub robot_id: String,
    pub session_id: String,
    pub principal: String,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub status: Status,
    pub battery_percent: u8,
    pub position_x_m: f64,
    pub position_y_m: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_camera: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_audio: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_identity: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "op",
    content = "request",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Request {
    Command(CommandRequest),
    Telemetry(TelemetryRequest),
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Envelope {
    Command {
        grant: Grant,
        request: CommandRequest,
        request_signature: String,
    },
    Telemetry {
        grant: Grant,
        request: TelemetryRequest,
        request_signature: String,
    },
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedCommand {
    pub robot_id: String,
    pub session_id: String,
    pub grant_id: String,
    pub sequence: u64,
    pub linear_mps: f64,
    pub angular_rps: f64,
    pub valid_until_ms: u64,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MinimalTelemetry {
    pub robot_id: String,
    pub status: Status,
    pub battery_percent: u8,
    pub position_cell_x: i64,
    pub position_cell_y: i64,
    pub position_grid_m: f64,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub schema: String,
    pub allowed: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<AuthorizedCommand>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<MinimalTelemetry>,
}
impl Decision {
    pub fn deny(reason: &str) -> Self {
        Self {
            schema: "robot-decision/v1".into(),
            allowed: false,
            reason: reason.into(),
            command: None,
            telemetry: None,
        }
    }
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn finite_limit(value: f64, maximum: f64) -> bool {
    value.is_finite() && value >= 0.0 && value <= maximum
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema == "robot-policy/v1", "Invalid policy schema");
        ensure!(
            [
                &self.robot_id,
                &self.session_id,
                &self.command_principal,
                &self.telemetry_principal
            ]
            .into_iter()
            .all(|x| identifier(x)),
            "Invalid policy identity"
        );
        ensure!(
            finite_limit(self.max_linear_mps, 5.0) && finite_limit(self.max_angular_rps, 5.0),
            "Invalid motion ceiling"
        );
        ensure!(
            (1..=5000).contains(&self.max_request_age_ms)
                && (1..=3_600_000).contains(&self.max_grant_ttl_ms),
            "Invalid time budget"
        );
        ensure!(
            (1..=1000).contains(&self.command_lease_ms)
                && self.command_lease_ms <= self.max_request_age_ms,
            "Invalid command lease"
        );
        ensure!(
            self.min_command_interval_ms <= 1000
                && self.position_grid_m.is_finite()
                && (1.0..=1000.0).contains(&self.position_grid_m),
            "Invalid rate or spatial policy"
        );
        Ok(())
    }
}
impl Claims {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema == "robot-grant/v1", "Invalid grant schema");
        ensure!(
            [
                &self.grant_id,
                &self.robot_id,
                &self.session_id,
                &self.principal
            ]
            .into_iter()
            .all(|x| identifier(x)),
            "Invalid grant identity"
        );
        public_key(&self.holder_public_key)?;
        ensure!(
            self.expires_at_ms > self.not_before_ms && self.expires_at_ms <= i64::MAX as u64,
            "Invalid grant time"
        );
        ensure!(
            self.expires_at_ms - self.not_before_ms <= 3_600_000,
            "Grant duration exceeds hard budget"
        );
        ensure!(
            !self.capabilities.is_empty()
                && self.capabilities.len() <= 2
                && self.capabilities.iter().collect::<BTreeSet<_>>().len()
                    == self.capabilities.len(),
            "Invalid capability set"
        );
        ensure!(
            finite_limit(self.max_linear_mps, 5.0) && finite_limit(self.max_angular_rps, 5.0),
            "Invalid grant motion ceiling"
        );
        Ok(())
    }
}
pub fn public_key(encoded: &str) -> Result<VerifyingKey> {
    ensure!(encoded.len() == 64, "Invalid public key");
    let bytes: [u8; 32] = hex::decode(encoded)
        .map_err(|_| anyhow!("Invalid public key"))?
        .try_into()
        .map_err(|_| anyhow!("Invalid public key"))?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| anyhow!("Invalid public key"))
}
fn signed_bytes<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>> {
    let mut bytes = domain.to_vec();
    bytes.extend(serde_json::to_vec(value)?);
    Ok(bytes)
}
pub fn issue(claims: Claims, key: &SigningKey) -> Result<Grant> {
    claims.validate()?;
    let signature = hex::encode(key.sign(&signed_bytes(GRANT_DOMAIN, &claims)?).to_bytes());
    Ok(Grant { claims, signature })
}
pub fn sign_request(grant: Grant, request: Request, key: &SigningKey) -> Result<Envelope> {
    ensure!(
        key.verifying_key() == public_key(&grant.claims.holder_public_key)?,
        "Holder key does not match grant"
    );
    let request_signature = hex::encode(
        key.sign(&signed_bytes(REQUEST_DOMAIN, &(&grant, &request))?)
            .to_bytes(),
    );
    Ok(match request {
        Request::Command(request) => Envelope::Command {
            grant,
            request,
            request_signature,
        },
        Request::Telemetry(request) => Envelope::Telemetry {
            grant,
            request,
            request_signature,
        },
    })
}
fn valid_signature<T: Serialize>(
    key: &VerifyingKey,
    signature: &str,
    domain: &[u8],
    value: &T,
) -> bool {
    if signature.len() != 128 {
        return false;
    }
    let Ok(bytes) = hex::decode(signature) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(bytes.as_slice()) else {
        return false;
    };
    let Ok(message) = signed_bytes(domain, value) else {
        return false;
    };
    key.verify_strict(&message, &signature).is_ok()
}
fn hash<T: Serialize>(value: &T) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}
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
        let (grant, request, signature) = match envelope {
            Envelope::Command {
                grant,
                request,
                request_signature,
            } => (grant, Request::Command(request), request_signature),
            Envelope::Telemetry {
                grant,
                request,
                request_signature,
            } => (grant, Request::Telemetry(request), request_signature),
        };
        let deny = |reason: &str| Ok(Decision::deny(reason));
        let claims = &grant.claims;
        if claims.validate().is_err()
            || !valid_signature(&self.authority, &grant.signature, GRANT_DOMAIN, claims)
        {
            return deny("invalid_grant");
        }
        let holder = public_key(&claims.holder_public_key)?;
        if !valid_signature(&holder, &signature, REQUEST_DOMAIN, &(&grant, &request)) {
            return deny("invalid_request_signature");
        }
        let (robot, session, principal, sequence, issued, capability, expected_principal) =
            match &request {
                Request::Command(r) => (
                    &r.robot_id,
                    &r.session_id,
                    &r.principal,
                    r.sequence,
                    r.issued_at_ms,
                    Capability::Command,
                    &self.policy.command_principal,
                ),
                Request::Telemetry(r) => (
                    &r.robot_id,
                    &r.session_id,
                    &r.principal,
                    r.sequence,
                    r.issued_at_ms,
                    Capability::Telemetry,
                    &self.policy.telemetry_principal,
                ),
            };
        if robot != &self.policy.robot_id
            || robot != &claims.robot_id
            || session != &self.policy.session_id
            || session != &claims.session_id
            || principal != expected_principal
            || principal != &claims.principal
        {
            return deny("identity_scope");
        }
        if !claims.capabilities.contains(&capability) {
            return deny("capability_scope");
        }
        if now < claims.not_before_ms
            || now >= claims.expires_at_ms
            || claims.expires_at_ms - claims.not_before_ms > self.policy.max_grant_ttl_ms
        {
            return deny("grant_time");
        }
        if issued < claims.not_before_ms
            || issued > now
            || now - issued >= self.policy.max_request_age_ms
            || now > i64::MAX as u64
            || sequence == 0
            || sequence > i64::MAX as u64
        {
            return deny("request_time_or_sequence");
        }
        let mut decision = Decision {
            schema: "robot-decision/v1".into(),
            allowed: true,
            reason: "authorized".into(),
            command: None,
            telemetry: None,
        };
        match &request {
            Request::Command(r) => {
                if !r.linear_mps.is_finite()
                    || !r.angular_rps.is_finite()
                    || r.linear_mps.abs() > self.policy.max_linear_mps.min(claims.max_linear_mps)
                    || r.angular_rps.abs() > self.policy.max_angular_rps.min(claims.max_angular_rps)
                {
                    return deny("motion_limit");
                }
                let valid_until_ms = now
                    .saturating_add(self.policy.command_lease_ms)
                    .min(issued.saturating_add(self.policy.max_request_age_ms))
                    .min(claims.expires_at_ms);
                decision.command = Some(AuthorizedCommand {
                    robot_id: robot.clone(),
                    session_id: session.clone(),
                    grant_id: claims.grant_id.clone(),
                    sequence,
                    linear_mps: r.linear_mps,
                    angular_rps: r.angular_rps,
                    valid_until_ms,
                });
            }
            Request::Telemetry(r) => {
                if r.battery_percent > 100
                    || !r.position_x_m.is_finite()
                    || !r.position_y_m.is_finite()
                    || r.position_x_m.abs() > 1_000_000.0
                    || r.position_y_m.abs() > 1_000_000.0
                    || [&r.raw_camera, &r.raw_audio, &r.operator_identity]
                        .into_iter()
                        .flatten()
                        .any(|x| x.len() > 16 * 1024)
                {
                    return deny("telemetry_limit");
                }
                decision.telemetry = Some(MinimalTelemetry {
                    robot_id: robot.clone(),
                    status: r.status.clone(),
                    battery_percent: r.battery_percent,
                    position_cell_x: (r.position_x_m / self.policy.position_grid_m).floor() as i64,
                    position_cell_y: (r.position_y_m / self.policy.position_grid_m).floor() as i64,
                    position_grid_m: self.policy.position_grid_m,
                });
            }
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let revoked: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM revocations WHERE grant_id=?1)",
            [&claims.grant_id],
            |r| r.get(0),
        )?;
        if revoked {
            return deny("revoked");
        }
        let fingerprint = hash(claims)?;
        let previous: Option<(String, i64, i64)> = tx
            .query_row(
                "SELECT fingerprint,sequence,last_ms FROM counters WHERE grant_id=?1",
                [&claims.grant_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((old_fingerprint, old_sequence, last_ms)) = previous {
            if old_fingerprint != fingerprint {
                return deny("grant_id_reused");
            }
            if sequence <= old_sequence as u64 {
                return deny("replay");
            }
            if now < last_ms as u64 {
                return deny("clock_rollback");
            }
            if matches!(request, Request::Command(_))
                && now - (last_ms as u64) < self.policy.min_command_interval_ms
            {
                return deny("rate_limit");
            }
        } else {
            let count: i64 = tx.query_row("SELECT COUNT(*) FROM counters", [], |r| r.get(0))?;
            if count >= MAX_GRANTS {
                return deny("state_budget");
            }
        }
        tx.execute("INSERT INTO counters(grant_id,fingerprint,sequence,last_ms) VALUES(?1,?2,?3,?4) ON CONFLICT(grant_id) DO UPDATE SET sequence=excluded.sequence,last_ms=excluded.last_ms",params![claims.grant_id,fingerprint,sequence as i64,now as i64])?;
        append_audit(&tx, now, &decision, digest)?;
        tx.commit()?;
        // Persist authorization before exposing output: crash between commit and
        // publication is uncertain delivery, never an excuse to replay a command.
        Ok(decision)
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

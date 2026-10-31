#![forbid(unsafe_code)]
//! Signed capabilities and bounded command/data policy, not a safety-rated controller.
use anyhow::{anyhow, ensure, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_GRANTS: i64 = 4096;
const MAX_REVOCATIONS: i64 = 4096;
#[cfg(feature = "native")]
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

#[cfg(feature = "native")]
mod native;
#[cfg(feature = "native")]
pub use native::{audit, revoke, AuditEvent, Guard};

struct Verified {
    grant_id: String,
    fingerprint: String,
    sequence: u64,
    is_command: bool,
    decision: Decision,
}

/// Shared cryptographic, identity, freshness, numeric and data projection checks.
/// Both the native SQLite guard and browser in-memory adapter call this function.
fn verify_request(
    policy: &Policy,
    authority: &VerifyingKey,
    envelope: Envelope,
    now: u64,
) -> std::result::Result<Verified, &'static str> {
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
    let deny = |reason: &'static str| Err(reason);
    let claims = &grant.claims;
    if claims.validate().is_err()
        || !valid_signature(authority, &grant.signature, GRANT_DOMAIN, claims)
    {
        return deny("invalid_grant");
    }
    let holder = public_key(&claims.holder_public_key).map_err(|_| "invalid_grant")?;
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
                &policy.command_principal,
            ),
            Request::Telemetry(r) => (
                &r.robot_id,
                &r.session_id,
                &r.principal,
                r.sequence,
                r.issued_at_ms,
                Capability::Telemetry,
                &policy.telemetry_principal,
            ),
        };
    if robot != &policy.robot_id
        || robot != &claims.robot_id
        || session != &policy.session_id
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
        || claims.expires_at_ms - claims.not_before_ms > policy.max_grant_ttl_ms
    {
        return deny("grant_time");
    }
    if issued < claims.not_before_ms
        || issued > now
        || now - issued >= policy.max_request_age_ms
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
                || r.linear_mps.abs() > policy.max_linear_mps.min(claims.max_linear_mps)
                || r.angular_rps.abs() > policy.max_angular_rps.min(claims.max_angular_rps)
            {
                return deny("motion_limit");
            }
            let valid_until_ms = now
                .saturating_add(policy.command_lease_ms)
                .min(issued.saturating_add(policy.max_request_age_ms))
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
                position_cell_x: (r.position_x_m / policy.position_grid_m).floor() as i64,
                position_cell_y: (r.position_y_m / policy.position_grid_m).floor() as i64,
                position_grid_m: policy.position_grid_m,
            });
        }
    }
    Ok(Verified {
        grant_id: claims.grant_id.clone(),
        fingerprint: hash(claims).map_err(|_| "invalid_grant")?,
        sequence,
        is_command: matches!(request, Request::Command(_)),
        decision,
    })
}

struct Admission {
    fingerprint: String,
    sequence: u64,
    last_ms: u64,
}

fn admission_denial(
    policy: &Policy,
    request: &Verified,
    previous: Option<&Admission>,
    revoked: bool,
    count: usize,
    now: u64,
) -> Option<Decision> {
    let reason = if revoked {
        Some("revoked")
    } else if let Some(previous) = previous {
        if previous.fingerprint != request.fingerprint {
            Some("grant_id_reused")
        } else if request.sequence <= previous.sequence {
            Some("replay")
        } else if now < previous.last_ms {
            Some("clock_rollback")
        } else if request.is_command && now - previous.last_ms < policy.min_command_interval_ms {
            Some("rate_limit")
        } else {
            None
        }
    } else if count >= MAX_GRANTS as usize {
        Some("state_budget")
    } else {
        None
    };
    reason.map(Decision::deny)
}

/// In-memory adapter for a public demonstration. It is not durable storage,
/// a ROS participant, an audit ledger, or a security boundary against its user.
/// The policy/signature/projection/admission checks are shared with `Guard`.
pub struct MemoryGuard {
    policy: Policy,
    authority: VerifyingKey,
    counters: BTreeMap<String, Admission>,
    revocations: BTreeSet<String>,
}
impl MemoryGuard {
    pub fn new(policy: Policy, authority: VerifyingKey) -> Result<Self> {
        policy.validate()?;
        Ok(Self {
            policy,
            authority,
            counters: BTreeMap::new(),
            revocations: BTreeSet::new(),
        })
    }
    pub fn process(&mut self, raw: &[u8], now: u64) -> Decision {
        if raw.len() > MAX_INPUT_BYTES {
            return Decision::deny("input_budget");
        }
        let envelope = match serde_json::from_slice::<Envelope>(raw) {
            Ok(envelope) => envelope,
            Err(_) => return Decision::deny("invalid_schema"),
        };
        let verified = match verify_request(&self.policy, &self.authority, envelope, now) {
            Ok(verified) => verified,
            Err(reason) => return Decision::deny(reason),
        };
        if let Some(denial) = admission_denial(
            &self.policy,
            &verified,
            self.counters.get(&verified.grant_id),
            self.revocations.contains(&verified.grant_id),
            self.counters.len(),
            now,
        ) {
            return denial;
        }
        self.counters.insert(
            verified.grant_id,
            Admission {
                fingerprint: verified.fingerprint,
                sequence: verified.sequence,
                last_ms: now,
            },
        );
        verified.decision
    }
    pub fn revoke(&mut self, grant_id: &str) -> Result<()> {
        ensure!(identifier(grant_id), "Invalid grant ID");
        ensure!(
            self.revocations.contains(grant_id)
                || self.revocations.len() < MAX_REVOCATIONS as usize,
            "Revocation budget exhausted"
        );
        self.revocations.insert(grant_id.to_string());
        Ok(())
    }
}

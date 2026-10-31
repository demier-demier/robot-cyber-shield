use ed25519_dalek::SigningKey;
use robot_cyber_shield::*;
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{Arc, Barrier},
};
use tempfile::TempDir;

const NOW: u64 = 1_000_000;
fn key() -> SigningKey {
    let mut seed = [0; 32];
    getrandom::fill(&mut seed).unwrap();
    SigningKey::from_bytes(&seed)
}
fn policy() -> Policy {
    Policy {
        schema: "robot-policy/v1".into(),
        robot_id: "r1".into(),
        session_id: "mission1".into(),
        command_principal: "planner".into(),
        telemetry_principal: "sensor".into(),
        max_linear_mps: 0.5,
        max_angular_rps: 0.8,
        max_request_age_ms: 2000,
        max_grant_ttl_ms: 3_600_000,
        min_command_interval_ms: 10,
        command_lease_ms: 250,
        position_grid_m: 1.0,
    }
}
struct Lab {
    _dir: TempDir,
    path: PathBuf,
    authority: SigningKey,
    holder: SigningKey,
    policy: Policy,
}
impl Lab {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        Self {
            _dir: dir,
            path,
            authority: key(),
            holder: key(),
            policy: policy(),
        }
    }
    fn guard(&self) -> Guard {
        Guard::open(
            &self.path,
            self.policy.clone(),
            self.authority.verifying_key(),
        )
        .unwrap()
    }
    fn claims(&self, telemetry: bool) -> Claims {
        Claims {
            schema: "robot-grant/v1".into(),
            grant_id: if telemetry {
                "sensor-grant"
            } else {
                "command-grant"
            }
            .into(),
            robot_id: "r1".into(),
            session_id: "mission1".into(),
            principal: if telemetry { "sensor" } else { "planner" }.into(),
            holder_public_key: hex::encode(self.holder.verifying_key().to_bytes()),
            not_before_ms: NOW - 10_000,
            expires_at_ms: NOW + 60_000,
            capabilities: vec![if telemetry {
                Capability::Telemetry
            } else {
                Capability::Command
            }],
            max_linear_mps: 0.5,
            max_angular_rps: 0.8,
        }
    }
    fn command(&self, seq: u64, issued: u64) -> Request {
        Request::Command(CommandRequest {
            robot_id: "r1".into(),
            session_id: "mission1".into(),
            principal: "planner".into(),
            sequence: seq,
            issued_at_ms: issued,
            linear_mps: 0.2,
            angular_rps: -0.1,
        })
    }
    fn telemetry(&self, seq: u64) -> Request {
        Request::Telemetry(TelemetryRequest {
            robot_id: "r1".into(),
            session_id: "mission1".into(),
            principal: "sensor".into(),
            sequence: seq,
            issued_at_ms: NOW,
            status: Status::Idle,
            battery_percent: 80,
            position_x_m: 1.234,
            position_y_m: -3.456,
            raw_camera: Some("SYNTHETIC_PRIVATE_CAMERA".into()),
            raw_audio: Some("SYNTHETIC_PRIVATE_AUDIO".into()),
            operator_identity: Some("SYNTHETIC_PRIVATE_PERSON".into()),
        })
    }
    fn signed(&self, claims: Claims, request: Request) -> Vec<u8> {
        serde_json::to_vec(
            &sign_request(
                issue(claims, &self.authority).unwrap(),
                request,
                &self.holder,
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn cmd(&self, seq: u64, issued: u64) -> Vec<u8> {
        self.signed(self.claims(false), self.command(seq, issued))
    }
}
fn deny(d: Decision, reason: &str) {
    assert!(!d.allowed, "unexpected allow");
    assert_eq!(d.reason, reason);
    assert!(d.command.is_none());
    assert!(d.telemetry.is_none());
}

#[test]
fn authorized_command_has_finite_bounded_lease_and_grant_identity() {
    let l = Lab::new();
    let mut g = l.guard();
    let d = g.process(&l.cmd(1, NOW), NOW);
    assert!(d.allowed);
    let c = d.command.unwrap();
    assert_eq!(c.valid_until_ms, NOW + 250);
    assert_eq!(c.grant_id, "command-grant");
    assert_eq!(c.linear_mps, 0.2);
    let mut claims = l.claims(false);
    claims.grant_id = "expires-soon".into();
    claims.expires_at_ms = NOW + 50;
    assert_eq!(
        g.process(&l.signed(claims, l.command(1, NOW)), NOW)
            .command
            .unwrap()
            .valid_until_ms,
        NOW + 50
    );
    assert_eq!(
        g.process(&l.cmd(2, NOW - 1900), NOW + 20)
            .command
            .unwrap()
            .valid_until_ms,
        NOW + 100
    );
}
#[test]
fn tampered_grant_request_and_forged_holder_are_denied() {
    let l = Lab::new();
    let mut g = l.guard();
    let raw = l.cmd(1, NOW);
    let mut v: Value = serde_json::from_slice(&raw).unwrap();
    v["grant"]["claims"]["max_linear_mps"] = json!(2.0);
    deny(
        g.process(&serde_json::to_vec(&v).unwrap(), NOW),
        "invalid_grant",
    );
    let mut v: Value = serde_json::from_slice(&raw).unwrap();
    v["request"]["linear_mps"] = json!(0.3);
    deny(
        g.process(&serde_json::to_vec(&v).unwrap(), NOW),
        "invalid_request_signature",
    );
    let mut v: Value = serde_json::from_slice(&raw).unwrap();
    v["request_signature"] = json!("00".repeat(64));
    deny(
        g.process(&serde_json::to_vec(&v).unwrap(), NOW),
        "invalid_request_signature",
    );
    assert!(sign_request(
        issue(l.claims(false), &l.authority).unwrap(),
        l.command(1, NOW),
        &key()
    )
    .is_err());
    assert!(g.process(&raw, NOW).allowed);
}
#[test]
fn valid_signed_grants_cannot_override_fixed_robot_session_or_principal() {
    let l = Lab::new();
    let mut g = l.guard();
    for field in ["robot", "session", "principal"] {
        let mut c = l.claims(false);
        let mut r = l.command(1, NOW);
        let Request::Command(ref mut r) = r else {
            unreachable!()
        };
        match field {
            "robot" => {
                c.robot_id = "r2".into();
                r.robot_id = "r2".into()
            }
            "session" => {
                c.session_id = "other".into();
                r.session_id = "other".into()
            }
            _ => {
                c.principal = "attacker".into();
                r.principal = "attacker".into()
            }
        }
        let r = Request::Command(r.clone());
        deny(g.process(&l.signed(c, r), NOW), "identity_scope");
    }
    let mut c = l.claims(false);
    c.capabilities = vec![Capability::Telemetry];
    deny(
        g.process(&l.signed(c, l.command(1, NOW)), NOW),
        "capability_scope",
    );
}
#[test]
fn expiry_not_before_ttl_stale_future_and_zero_sequence_fail_closed() {
    let mut l = Lab::new();
    l.policy.max_grant_ttl_ms = 100_000;
    let mut g = l.guard();
    let mut c = l.claims(false);
    c.expires_at_ms = NOW;
    deny(
        g.process(&l.signed(c, l.command(1, NOW)), NOW),
        "grant_time",
    );
    let mut c = l.claims(false);
    c.not_before_ms = NOW + 1;
    deny(
        g.process(&l.signed(c, l.command(1, NOW)), NOW),
        "grant_time",
    );
    let mut c = l.claims(false);
    c.expires_at_ms = NOW + 100_000;
    deny(
        g.process(&l.signed(c, l.command(1, NOW)), NOW),
        "grant_time",
    );
    for (seq, t) in [(1, NOW - 2000), (1, NOW + 1), (0, NOW), (u64::MAX, NOW)] {
        deny(g.process(&l.cmd(seq, t), NOW), "request_time_or_sequence");
    }
}
#[test]
fn motion_limit_intersects_policy_and_grant_ceiling() {
    let l = Lab::new();
    let mut g = l.guard();
    for (linear, angular) in [
        (0.50001, 0.0),
        (-0.50001, 0.0),
        (0.0, 0.80001),
        (0.0, -0.80001),
    ] {
        let Request::Command(mut r) = l.command(1, NOW) else {
            unreachable!()
        };
        r.linear_mps = linear;
        r.angular_rps = angular;
        deny(
            g.process(&l.signed(l.claims(false), Request::Command(r)), NOW),
            "motion_limit",
        );
    }
    let mut c = l.claims(false);
    c.max_linear_mps = 0.1;
    deny(
        g.process(&l.signed(c, l.command(1, NOW)), NOW),
        "motion_limit",
    );
}
#[test]
fn strict_schema_rejects_unknown_duplicate_fields_nonfinite_and_trailing_json() {
    let l = Lab::new();
    let mut g = l.guard();
    let raw = l.cmd(1, NOW);
    let text = String::from_utf8(raw.clone()).unwrap();
    for value in [
        text.replace("0.2", "NaN"),
        text.replace("0.2", "Infinity"),
        text.replace("0.2", "1e999"),
        format!("{text}{{}}"),
        text.replace("\"sequence\":1", "\"sequence\":1,\"sequence\":2"),
    ] {
        deny(g.process(value.as_bytes(), NOW), "invalid_schema");
    }
    let mut v: Value = serde_json::from_slice(&raw).unwrap();
    v["request"]["metadata"] = json!({"secret":"NO_ECHO"});
    let d = g.process(&serde_json::to_vec(&v).unwrap(), NOW);
    assert!(!serde_json::to_string(&d).unwrap().contains("NO_ECHO"));
    deny(d, "invalid_schema");
    let mut v: Value = serde_json::from_slice(&raw).unwrap();
    v["extra"] = json!(true);
    deny(
        g.process(&serde_json::to_vec(&v).unwrap(), NOW),
        "invalid_schema",
    );
}
#[test]
fn replay_and_revocation_persist_across_restarts() {
    let l = Lab::new();
    {
        let mut g = l.guard();
        assert!(g.process(&l.cmd(1, NOW), NOW).allowed);
    }
    {
        let mut g = l.guard();
        deny(g.process(&l.cmd(1, NOW), NOW + 20), "replay");
        assert!(g.process(&l.cmd(2, NOW + 20), NOW + 20).allowed);
    }
    revoke(&l.path, "command-grant").unwrap();
    revoke(&l.path, "command-grant").unwrap();
    let mut g = l.guard();
    deny(g.process(&l.cmd(3, NOW + 40), NOW + 40), "revoked");
}
#[test]
fn reused_grant_ids_rate_limits_and_clock_rollback_are_denied() {
    let l = Lab::new();
    let mut g = l.guard();
    assert!(g.process(&l.cmd(1, NOW), NOW).allowed);
    let mut c = l.claims(false);
    c.expires_at_ms += 1;
    deny(
        g.process(&l.signed(c, l.command(2, NOW + 20)), NOW + 20),
        "grant_id_reused",
    );
    deny(g.process(&l.cmd(2, NOW + 1), NOW + 1), "rate_limit");
    deny(g.process(&l.cmd(2, NOW - 1), NOW - 1), "clock_rollback");
    assert!(g.process(&l.cmd(2, NOW + 10), NOW + 10).allowed);
}
#[test]
fn concurrent_guard_connections_admit_duplicate_only_once() {
    let l = Lab::new();
    let g1 = l.guard();
    let g2 = l.guard();
    let raw = l.cmd(1, NOW);
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = [g1, g2]
        .into_iter()
        .map(|mut g| {
            let raw = raw.clone();
            let b = barrier.clone();
            std::thread::spawn(move || {
                b.wait();
                g.process(&raw, NOW)
            })
        })
        .collect();
    let decisions: Vec<_> = handles.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(decisions.iter().filter(|d| d.allowed).count(), 1);
    assert!(decisions.iter().any(|d| d.reason == "replay"));
}
#[test]
fn telemetry_projection_excludes_raw_personal_and_exact_position_fields() {
    let l = Lab::new();
    let mut g = l.guard();
    let raw = l.signed(l.claims(true), l.telemetry(1));
    let d = g.process(&raw, NOW);
    assert!(d.allowed);
    let v = serde_json::to_value(d).unwrap();
    assert_eq!(
        v["telemetry"],
        json!({"robot_id":"r1","status":"idle","battery_percent":80,"position_cell_x":1,"position_cell_y":-4,"position_grid_m":1.0})
    );
    let audit = serde_json::to_string(&audit(&l.path, 100).unwrap()).unwrap();
    assert!(!audit.contains("SYNTHETIC_PRIVATE"));
    assert!(!audit.contains("1.234"));
}
#[test]
fn invalid_telemetry_and_arbitrary_metadata_cannot_be_forwarded() {
    let l = Lab::new();
    let mut g = l.guard();
    for mode in 0..3 {
        let Request::Telemetry(mut r) = l.telemetry(1) else {
            unreachable!()
        };
        match mode {
            0 => r.battery_percent = 101,
            1 => r.position_x_m = 1_000_001.0,
            _ => r.raw_camera = Some("x".repeat(16 * 1024 + 1)),
        };
        deny(
            g.process(&l.signed(l.claims(true), Request::Telemetry(r)), NOW),
            "telemetry_limit",
        );
    }
    let mut v: Value = serde_json::from_slice(&l.signed(l.claims(true), l.telemetry(1))).unwrap();
    v["request"]["metadata"] = json!({"face":"private"});
    deny(
        g.process(&serde_json::to_vec(&v).unwrap(), NOW),
        "invalid_schema",
    );
}
#[test]
fn state_binds_authority_and_policy_and_rejects_invalid_policy() {
    let l = Lab::new();
    drop(l.guard());
    let mut changed = l.policy.clone();
    changed.max_linear_mps = 0.4;
    assert!(Guard::open(&l.path, changed, l.authority.verifying_key()).is_err());
    assert!(Guard::open(&l.path, l.policy.clone(), key().verifying_key()).is_err());
    let mut changed = l.policy.clone();
    changed.command_lease_ms = 0;
    assert!(Guard::open(&l.path, changed, l.authority.verifying_key()).is_err());
    let mut changed = l.policy.clone();
    changed.max_linear_mps = f64::NAN;
    assert!(changed.validate().is_err());
}
#[test]
fn unavailable_audit_rolls_back_sequence_and_never_returns_command() {
    let l = Lab::new();
    let mut g = l.guard();
    let db = rusqlite::Connection::open(&l.path).unwrap();
    db.execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(FAIL,'synthetic storage failure'); END;").unwrap();
    deny(g.process(&l.cmd(1, NOW), NOW), "state_unavailable");
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM counters", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
    db.execute_batch("DROP TRIGGER fail_audit").unwrap();
    assert!(g.process(&l.cmd(1, NOW), NOW).allowed);
}
#[test]
fn locked_state_never_emits_an_authorized_command() {
    let l = Lab::new();
    let mut g = l.guard();
    let db = rusqlite::Connection::open(&l.path).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    deny(g.process(&l.cmd(1, NOW), NOW), "state_unavailable");
    db.execute_batch("ROLLBACK").unwrap();
    assert!(g.process(&l.cmd(1, NOW), NOW).allowed);
}
#[test]
fn audit_is_bounded_ordered_and_contains_no_raw_payloads() {
    let l = Lab::new();
    let mut g = l.guard();
    for i in 0..2050 {
        deny(
            g.process(b"{\"secret\":\"PRIVATE_SYNTHETIC_VALUE\"}", NOW + i),
            "invalid_schema",
        );
    }
    let events = audit(&l.path, 2048).unwrap();
    assert_eq!(events.len(), 2048);
    assert_eq!(events.first().unwrap().id, 2050);
    assert_eq!(events.last().unwrap().id, 3);
    assert!(events.windows(2).all(|w| w[0].id > w[1].id));
    assert!(events
        .iter()
        .all(|e| !e.allowed && e.reason == "invalid_schema" && e.input_sha256.len() == 64));
    assert!(!serde_json::to_string(&events)
        .unwrap()
        .contains("PRIVATE_SYNTHETIC_VALUE"));
    assert!(audit(&l.path, 0).is_err());
}
#[test]
fn oversized_library_input_is_bounded_and_never_echoed() {
    let l = Lab::new();
    let mut g = l.guard();
    deny(
        g.process(&vec![b'x'; MAX_INPUT_BYTES + 1], NOW),
        "input_budget",
    );
    assert_eq!(audit(&l.path, 1).unwrap()[0].reason, "input_budget");
}
#[test]
fn state_and_revocation_capacity_fail_closed() {
    let l = Lab::new();
    let mut g = l.guard();
    let db = rusqlite::Connection::open(&l.path).unwrap();
    db.execute_batch("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4096) INSERT INTO counters(grant_id,fingerprint,sequence,last_ms) SELECT 'synthetic-'||x,'hash',1,1000000 FROM n").unwrap();
    deny(g.process(&l.cmd(1, NOW), NOW), "state_budget");
    db.execute_batch("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4096) INSERT INTO revocations(grant_id) SELECT 'revoked-'||x FROM n").unwrap();
    assert!(revoke(&l.path, "extra").is_err());
    assert!(revoke(&l.path, "revoked-1").is_ok());
}
#[cfg(unix)]
#[test]
fn database_sidecars_are_private_and_symlinks_or_public_state_are_rejected() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let l = Lab::new();
    let _g = l.guard();
    for suffix in ["", "-wal", "-shm"] {
        let name = format!("{}{}", l.path.display(), suffix);
        if let Ok(m) = std::fs::metadata(&name) {
            assert_eq!(m.permissions().mode() & 0o077, 0);
        }
    }
    let link = l._dir.path().join("link.db");
    symlink(&l.path, &link).unwrap();
    assert!(Guard::open(&link, l.policy.clone(), l.authority.verifying_key()).is_err());
    std::fs::set_permissions(&l.path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Guard::open(&l.path, l.policy.clone(), l.authority.verifying_key()).is_err());
}

#[test]
fn corrupt_state_is_rejected_at_startup() {
    let l = Lab::new();
    drop(l.guard());
    std::fs::write(&l.path, b"synthetic corrupt database").unwrap();
    assert!(Guard::open(&l.path, l.policy.clone(), l.authority.verifying_key()).is_err());
}
#[cfg(unix)]
#[test]
fn dangling_wal_symlink_is_rejected_before_database_open() {
    use std::os::unix::fs::symlink;
    let l = Lab::new();
    let sidecar = std::path::PathBuf::from(format!("{}-wal", l.path.display()));
    let target = l._dir.path().join("must-not-be-created");
    symlink(&target, &sidecar).unwrap();
    assert!(Guard::open(&l.path, l.policy.clone(), l.authority.verifying_key()).is_err());
    assert!(!target.exists());
    assert!(!l.path.exists());
}
#[test]
fn requests_must_be_issued_after_grant_activation() {
    let l = Lab::new();
    let mut g = l.guard();
    let mut c = l.claims(false);
    c.not_before_ms = NOW;
    deny(
        g.process(&l.signed(c, l.command(1, NOW - 1)), NOW),
        "request_time_or_sequence",
    );
}

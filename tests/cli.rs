use ed25519_dalek::SigningKey;
use robot_cyber_shield::{
    audit, issue, sign_request, Capability, Claims, CommandRequest, Policy, Request,
    MAX_INPUT_BYTES,
};
use serde_json::Value;
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_robot-cyber-shield"))
}
fn fixture(dir: &Path) -> (std::path::PathBuf, Vec<u8>) {
    let mut seed = [0; 32];
    getrandom::fill(&mut seed).unwrap();
    let authority = SigningKey::from_bytes(&seed);
    getrandom::fill(&mut seed).unwrap();
    let holder = SigningKey::from_bytes(&seed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let policy = Policy {
        schema: "robot-policy/v1".into(),
        robot_id: "robot".into(),
        session_id: "session".into(),
        command_principal: "planner".into(),
        telemetry_principal: "sensor".into(),
        max_linear_mps: 0.5,
        max_angular_rps: 0.8,
        max_request_age_ms: 5000,
        max_grant_ttl_ms: 3_600_000,
        min_command_interval_ms: 0,
        command_lease_ms: 250,
        position_grid_m: 1.0,
    };
    fs::write(
        dir.join("policy.json"),
        serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    fs::write(
        dir.join("authority.pub"),
        hex::encode(authority.verifying_key().to_bytes()),
    )
    .unwrap();
    let claims = Claims {
        schema: "robot-grant/v1".into(),
        grant_id: "grant".into(),
        robot_id: "robot".into(),
        session_id: "session".into(),
        principal: "planner".into(),
        holder_public_key: hex::encode(holder.verifying_key().to_bytes()),
        not_before_ms: now - 1000,
        expires_at_ms: now + 30_000,
        capabilities: vec![Capability::Command],
        max_linear_mps: 0.5,
        max_angular_rps: 0.8,
    };
    let request = Request::Command(CommandRequest {
        robot_id: "robot".into(),
        session_id: "session".into(),
        principal: "planner".into(),
        sequence: 1,
        issued_at_ms: now,
        linear_mps: 0.2,
        angular_rps: 0.1,
    });
    let raw = serde_json::to_vec(
        &sign_request(issue(claims, &authority).unwrap(), request, &holder).unwrap(),
    )
    .unwrap();
    (dir.join("state.db"), raw)
}
fn serve(dir: &Path, input: &[u8]) -> std::process::Output {
    let mut child = bin()
        .arg("serve")
        .arg("--state")
        .arg(dir.join("state.db"))
        .arg("--policy")
        .arg(dir.join("policy.json"))
        .arg("--public-key")
        .arg(dir.join("authority.pub"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let _ = stdin.write_all(input);
    drop(stdin);
    child.wait_with_output().unwrap()
}
#[test]
fn json_lines_cli_authorizes_then_rejects_replay_and_exports_audit() {
    let dir = tempfile::tempdir().unwrap();
    let (state, raw) = fixture(dir.path());
    let mut input = raw.clone();
    input.push(b'\n');
    input.extend_from_slice(&raw);
    input.push(b'\n');
    let output = serve(dir.path(), &input);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let decisions: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|x| serde_json::from_str(x).unwrap())
        .collect();
    assert_eq!(decisions.len(), 2);
    assert_eq!(decisions[0]["allowed"], true);
    assert_eq!(decisions[1]["reason"], "replay");
    assert!(decisions[1].get("command").is_none());
    let out = bin()
        .arg("audit")
        .arg("--state")
        .arg(&state)
        .output()
        .unwrap();
    assert!(out.status.success());
    let events: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["reason"], "replay");
    assert_eq!(events[1]["reason"], "authorized");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("holder_public_key"));
}
#[test]
fn oversized_frame_is_audited_and_terminates_before_valid_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let (state, raw) = fixture(dir.path());
    let mut input = vec![b'x'; MAX_INPUT_BYTES + 2];
    input.push(b'\n');
    input.extend_from_slice(&raw);
    input.push(b'\n');
    let out = serve(dir.path(), &input);
    assert!(out.status.success());
    let output = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<_> = output.lines().collect();
    assert_eq!(lines.len(), 1);
    let v: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(v["reason"], "input_budget");
    assert!(v.get("command").is_none());
    let events = audit(&state, 100).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].reason, "input_budget");
}
#[test]
fn keygen_never_overwrites_existing_key_and_uses_private_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let private = dir.path().join("key");
    let public = dir.path().join("key.pub");
    let mut cmd = bin();
    cmd.arg("keygen")
        .arg("--private-key")
        .arg(&private)
        .arg("--public-key")
        .arg(&public);
    assert!(cmd.output().unwrap().status.success());
    let before = fs::read(&private).unwrap();
    assert_eq!(before.len(), 65);
    assert!(!cmd.output().unwrap().status.success());
    assert_eq!(fs::read(&private).unwrap(), before);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [&private, &public] {
            assert_eq!(fs::metadata(p).unwrap().permissions().mode() & 0o077, 0);
        }
    }
}

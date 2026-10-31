use robot_cyber_shield::{public_key, revoke, Guard, MemoryGuard, Policy};
use serde_json::{json, Value};

fn fixtures() -> Value {
    serde_json::from_str(include_str!("../web/wasm/demo-fixtures.json")).unwrap()
}

#[test]
fn public_browser_fixtures_match_native_sqlite_decisions() {
    let fixture = fixtures();
    let policy: Policy = serde_json::from_value(fixture["policy"].clone()).unwrap();
    let authority = public_key(fixture["authority_public_key"].as_str().unwrap()).unwrap();
    for (name, scenario) in fixture["scenarios"].as_object().unwrap() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state.sqlite");
        let mut native = Guard::open(&state, policy.clone(), authority).unwrap();
        let mut memory = MemoryGuard::new(policy.clone(), authority).unwrap();
        if let Some(grant_id) = scenario["revoke_before"].as_str() {
            revoke(&state, grant_id).unwrap();
            memory.revoke(grant_id).unwrap();
        }
        for (index, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            let bytes = serde_json::to_vec(&step["envelope"]).unwrap();
            let now = step["now_ms"].as_u64().unwrap();
            let actual_native = serde_json::to_value(native.process(&bytes, now)).unwrap();
            let actual_memory = serde_json::to_value(memory.process(&bytes, now)).unwrap();
            assert_eq!(actual_native, actual_memory, "{name}/{index}");
            assert_eq!(
                actual_native["reason"], scenario["expected_reasons"][index],
                "{name}/{index}"
            );
        }
    }
}

#[test]
fn memory_adapter_strict_parse_and_hostile_numeric_inputs_fail_closed() {
    let fixture = fixtures();
    let policy: Policy = serde_json::from_value(fixture["policy"].clone()).unwrap();
    let authority = public_key(fixture["authority_public_key"].as_str().unwrap()).unwrap();
    let mut guard = MemoryGuard::new(policy, authority).unwrap();
    let now = fixture["logical_now_ms"].as_u64().unwrap();
    let original = fixture["scenarios"]["authorized"]["steps"][0]["envelope"].clone();
    let mut forged = original.clone();
    forged["request"]["linear_mps"] = json!(0.49);
    let decision = guard.process(&serde_json::to_vec(&forged).unwrap(), now);
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "invalid_request_signature");
    let malformed = serde_json::to_string(&original)
        .unwrap()
        .replace("0.25", "1e999");
    assert_eq!(
        guard.process(malformed.as_bytes(), now).reason,
        "invalid_schema"
    );
    assert_eq!(
        guard.process(&vec![b'x'; 65537], now).reason,
        "input_budget"
    );
    let allowed = guard.process(&serde_json::to_vec(&original).unwrap(), now);
    assert!(
        allowed.allowed,
        "denials must not consume the valid command sequence"
    );
}

#![forbid(unsafe_code)]
use robot_cyber_shield::{public_key, MemoryGuard, Policy, MAX_INPUT_BYTES};
use wasm_bindgen::prelude::*;

/// Live verification using the same Rust rules as the native guard.
/// This adapter has only in-memory state and uses an explicit logical clock.
#[wasm_bindgen]
pub struct BrowserGuard {
    inner: MemoryGuard,
}
#[wasm_bindgen]
impl BrowserGuard {
    #[wasm_bindgen(constructor)]
    pub fn new(policy_json: &str, authority_hex: &str) -> Result<BrowserGuard, JsValue> {
        if policy_json.len() > MAX_INPUT_BYTES {
            return Err(JsValue::from_str("Policy exceeds input budget"));
        }
        let policy: Policy =
            serde_json::from_str(policy_json).map_err(|_| JsValue::from_str("Invalid policy"))?;
        let authority =
            public_key(authority_hex).map_err(|_| JsValue::from_str("Invalid authority"))?;
        let inner =
            MemoryGuard::new(policy, authority).map_err(|_| JsValue::from_str("Invalid policy"))?;
        Ok(Self { inner })
    }
    pub fn decide(&mut self, envelope_json: &str, logical_now_ms: f64) -> Result<String, JsValue> {
        if !logical_now_ms.is_finite()
            || logical_now_ms < 0.0
            || logical_now_ms.fract() != 0.0
            || logical_now_ms > 9_007_199_254_740_991.0
        {
            return Err(JsValue::from_str("Invalid logical clock"));
        }
        let decision = self
            .inner
            .process(envelope_json.as_bytes(), logical_now_ms as u64);
        serde_json::to_string(&decision).map_err(|_| JsValue::from_str("Decision encoding failed"))
    }
    pub fn revoke(&mut self, grant_id: &str) -> Result<(), JsValue> {
        self.inner
            .revoke(grant_id)
            .map_err(|_| JsValue::from_str("Invalid revocation"))
    }
}

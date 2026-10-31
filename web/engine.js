// Live Rust WebAssembly verifier. No JavaScript allow/deny implementation.
// The renderer is illustrative; DDS access evidence comes from recorded ROS tests.
import init, { BrowserGuard } from './wasm/robot_shield_browser.js';

let initialized;
const FIXTURES_URL = new URL('./wasm/demo-fixtures.json', import.meta.url);

export async function createEngine() {
  if (!initialized) initialized = init().catch(error => { initialized = undefined; throw error; });
  await initialized;
  const response = await fetch(FIXTURES_URL);
  if (!response.ok) throw new Error('Signed demonstration fixtures could not be loaded.');
  const fixture = await response.json();
  if (fixture.schema !== 'robot-shield-browser-fixtures/v1') {
    throw new Error('Unknown signed fixture format.');
  }
  let guard;
  const reset = () => {
    if (guard) guard.free();
    guard = new BrowserGuard(JSON.stringify(fixture.policy), fixture.authority_public_key);
  };
  reset();
  const inspect = (envelope, logicalNowMs = fixture.logical_now_ms) => {
    const input = typeof envelope === 'string' ? envelope : JSON.stringify(envelope);
    return JSON.parse(guard.decide(input, logicalNowMs));
  };
  return {
    mode: 'live-rust-wasm',
    clock: 'recorded_mission_clock',
    statePersistence: 'memory',
    scenarios: Object.keys(fixture.scenarios),
    reset,
    inspect,
    getFixture(id) {
      const scenario = fixture.scenarios[id];
      if (!scenario) throw new Error('Unknown verification scenario.');
      return structuredClone(scenario);
    },
    runScenario(id) {
      const scenario = fixture.scenarios[id];
      if (!scenario) throw new Error('Unknown verification scenario.');
      reset();
      if (scenario.revoke_before) guard.revoke(scenario.revoke_before);
      const decisions = scenario.steps.map(step => inspect(step.envelope, step.now_ms));
      // A corrupted build/fixture fails visibly; expected labels never grant access.
      if (decisions.some((decision, index) => decision.reason !== scenario.expected_reasons[index])) {
        throw new Error('The verifier disagreed with the signed fixture acceptance check.');
      }
      // Integrate only velocities actually admitted by Rust, bounded by each
      // command lease. This is an illustrative straight-line kinematic model,
      // not physics or hardware execution. A denial never renews the lease.
      const startMs = scenario.steps[0].now_ms;
      let cursorMs = startMs, active = null, distanceM = 0;
      const advance = untilMs => {
        if (active && cursorMs < active.valid_until_ms) {
          const endMs = Math.min(untilMs, active.valid_until_ms);
          if (endMs > cursorMs) distanceM += active.linear_mps * (endMs - cursorMs) / 1000;
        }
        cursorMs = untilMs;
      };
      decisions.forEach((item, index) => {
        advance(scenario.steps[index].now_ms);
        if (item.allowed && item.command) active = item.command;
      });
      if (active && active.valid_until_ms > cursorMs) advance(active.valid_until_ms);
      const decision = decisions.at(-1);
      const lastStep = scenario.steps.at(-1);
      const request = lastStep.envelope.request;
      return {
        id, mode: 'live-rust-wasm', evidenceKind: 'live-rust-verification',
        clock: 'recorded_mission_clock', statePersistence: 'memory',
        logicalNowMs: lastStep.now_ms,
        decision, decisions,
        inputSummary: {
          operation: lastStep.envelope.op,
          requestedLinearMps: request.linear_mps ?? null,
          submittedFields: Object.keys(request),
          rawCameraIncluded: Object.hasOwn(request, 'raw_camera'),
          signedMission: lastStep.envelope.grant.claims.grant_id,
          signedRequestCount: scenario.steps.length,
        },
        outputSummary: {
          allowed: decision.allowed, reason: decision.reason,
          forwardedFields: Object.keys(decision.command || decision.telemetry || {}),
          forwardedCommand: decision.command || null,
          forwardedTelemetry: decision.telemetry || null,
        },
        renderer: {
          movementAllowed: decisions.some(item => item.allowed && item.command),
          linearMps: active?.linear_mps ?? 0,
          durationMs: cursorMs - startMs,
          distanceM,
          source: 'illustrative_kinematic_integration_of_verified_commands',
        },
      };
    },
    dispose() { if (guard) { guard.free(); guard = null; } },
  };
}

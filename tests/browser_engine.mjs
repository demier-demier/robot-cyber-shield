// Actual web/engine.js + emitted Rust WASM, using local file reads in place of HTTP.
// No policy outcomes are substituted. Browser QA separately exercises real HTTP.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, options) => {
  const address = url instanceof URL ? url : new URL(url);
  if (address.protocol !== 'file:') return realFetch(url, options);
  const bytes = await readFile(address);
  return new Response(bytes, { headers: {'Content-Type': address.pathname.endsWith('.wasm') ? 'application/wasm' : 'application/json'} });
};
const { createEngine } = await import('../web/engine.js');
const engine = await createEngine();
try {
  const authorized = engine.runScenario('authorized');
  assert.equal(authorized.decision.allowed, true);
  assert.equal(authorized.decisions.length, 28);
  assert.equal(authorized.renderer.durationMs, 2950);
  assert(Math.abs(authorized.renderer.distanceM - 0.7375) < 1e-10);
  for (const id of ['tamper','wrong_holder','overspeed','expired','revoked']) {
    const result = engine.runScenario(id);
    assert.equal(result.decision.allowed, false, id);
    assert.equal(result.renderer.distanceM, 0, id);
    assert.equal(result.renderer.movementAllowed, false, id);
  }
  const replay = engine.runScenario('replay');
  assert.deepEqual(replay.decisions.map(x => x.reason), ['authorized','replay']);
  assert.equal(replay.renderer.distanceM, 0.0625);
  assert.equal(replay.renderer.durationMs, 250);
  const telemetry = engine.runScenario('telemetry');
  assert.equal(telemetry.decision.allowed, true);
  assert.equal(telemetry.renderer.distanceM, 0);
  assert.equal(telemetry.outputSummary.forwardedFields.length, 6);
  assert(!telemetry.outputSummary.forwardedFields.includes('raw_camera'));
  const copied = engine.getFixture('authorized');
  copied.steps[0].envelope.request.linear_mps = 0.49;
  engine.reset();
  assert.equal(engine.inspect(copied.steps[0].envelope).reason, 'invalid_request_signature');
  assert.throws(() => engine.runScenario('not-a-scenario'), /Unknown verification scenario/);
  console.log(JSON.stringify({schema:'robot-shield-engine-check/v1',passed:true,scenarios:8,authorizedCommands:28,authorizedDistanceM:authorized.renderer.distanceM,replayDistanceM:replay.renderer.distanceM,zeroUnauthorizedMotion:true}));
} finally { engine.dispose(); globalThis.fetch = realFetch; }

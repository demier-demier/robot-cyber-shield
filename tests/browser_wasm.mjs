// Execute the emitted WASM binary in Node. This tests the actual compiled artifact,
// not a JavaScript copy of policy rules. Browser UI execution is a separate QA step.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const dir = new URL('../web/wasm/', import.meta.url);
const source = await readFile(new URL('robot_shield_browser.js', dir), 'utf8');
const module = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
await module.default({ module_or_path: await readFile(new URL('robot_shield_browser_bg.wasm', dir)) });
const fixture = JSON.parse(await readFile(new URL('demo-fixtures.json', dir), 'utf8'));
let decisions = 0;
for (const [name, scenario] of Object.entries(fixture.scenarios)) {
  const guard = new module.BrowserGuard(JSON.stringify(fixture.policy), fixture.authority_public_key);
  try {
    if (scenario.revoke_before) guard.revoke(scenario.revoke_before);
    const observed = scenario.steps.map(step => JSON.parse(guard.decide(JSON.stringify(step.envelope), step.now_ms)));
    assert.deepEqual(observed.map(d => d.reason), scenario.expected_reasons, name);
    if (name === 'telemetry') {
      assert.deepEqual(Object.keys(observed[0].telemetry).sort(), ['robot_id','status','battery_percent','position_cell_x','position_cell_y','position_grid_m'].sort());
      assert(!JSON.stringify(observed[0]).includes('SYNTHETIC_DEMO_'));
    }
    for (const decision of observed) if (!decision.allowed) {
      assert(!decision.command && !decision.telemetry, name + ': denied data must not leak');
    }
    decisions += observed.length;
  } finally { guard.free(); }
}
const guard = new module.BrowserGuard(JSON.stringify(fixture.policy), fixture.authority_public_key);
try {
  for (const now of [NaN, Infinity, -1, 1.5, 9007199254740992]) {
    assert.throws(() => guard.decide('{}', now), /Invalid logical clock/);
  }
  assert.equal(JSON.parse(guard.decide('x'.repeat(65537), fixture.logical_now_ms)).reason, 'input_budget');
  const extra = structuredClone(fixture.scenarios.authorized.steps[0].envelope);
  extra.injected = true;
  assert.equal(JSON.parse(guard.decide(JSON.stringify(extra), fixture.logical_now_ms)).reason, 'invalid_schema');
} finally { guard.free(); }
console.log(JSON.stringify({schema:'robot-shield-wasm-check/v1', passed:true, scenarios:Object.keys(fixture.scenarios).length, actualWasmDecisions:decisions, invalidClockChecks:5, memoryOnly:true, rosRuntimeTested:false}));

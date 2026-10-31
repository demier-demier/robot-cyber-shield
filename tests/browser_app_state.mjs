// Execute the actual app module with explicit lifecycle fault-injection peers.
// Minimal DOM, verifier and scene stubs isolate UI state handling. This is not
// browser rendering, WASM authorization or ROS validation; those have separate
// tests. Run with: node --experimental-vm-modules tests/browser_app_state.mjs
import vm from 'node:vm';
import fs from 'node:fs';
import assert from 'node:assert/strict';

const app = fs.readFileSync(new URL('../web/app.js', import.meta.url), 'utf8');
const evidence = JSON.parse(fs.readFileSync(new URL('../web/data/ros-evidence.json', import.meta.url), 'utf8'));

class Element {
  constructor(dataset = {}) {
    this.dataset = dataset;
    this.events = {};
    this.children = [];
    this.nodes = {};
    this.disabled = false;
    this.hidden = false;
    this.innerHTML = '';
    this.textContent = '';
    const classes = new Set();
    this.classList = {
      add: name => classes.add(name),
      remove: name => classes.delete(name),
      contains: name => classes.has(name),
      toggle: (name, force) => {
        const enabled = force ?? !classes.has(name);
        if (enabled) classes.add(name); else classes.delete(name);
        return enabled;
      },
    };
  }
  addEventListener(type, callback) { this.events[type] = callback; }
  setAttribute() {}
  querySelector(selector) { return this.nodes[selector] ??= new Element(); }
  append(...children) { this.children.push(...children); }
  replaceChildren() { this.children = []; }
  scrollIntoView() {}
  // Deliberately invoke even a disabled button's handler: it must also guard
  // against stale results, rather than relying exclusively on disabled styling.
  click() { this.events.click?.({}); }
}

async function harness({ reducedMotion, failTamper }) {
  const elements = new Map();
  const get = id => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const cases = ['authorized', 'tamper', 'camera', 'replay', 'telemetry']
    .map(id => new Element({ case: id }));
  const languages = ['en', 'pt'].map(lang => new Element({ lang }));
  const document = {
    getElementById: get,
    querySelectorAll: selector => selector === '[data-case]' ? cases
      : selector === '[data-lang]' ? languages : [],
    documentElement: { lang: 'en' },
    body: new Element(),
    createElement: () => new Element(),
    addEventListener() {},
    hidden: false,
  };
  const sceneEvents = [];
  const scene = {
    available: true,
    reset() {},
    setMode: value => sceneEvents.push(['mode', value]),
    setProgress: value => sceneEvents.push(['progress', value]),
    setPaused: value => sceneEvents.push(['paused', value]),
    resize() {},
  };
  const engine = {
    runScenario(id) {
      if (failTamper && id === 'tamper') throw new Error('Injected verifier failure');
      const allowed = ['authorized', 'telemetry'].includes(id);
      const decision = { allowed, reason: allowed ? 'authorized' : 'invalid_request_signature' };
      if (id === 'authorized') decision.command = { linear_mps: 0.25, valid_until_ms: 1000 };
      if (id === 'telemetry') decision.telemetry = { battery_percent: 80 };
      return {
        id, mode: 'live-rust-wasm', decision, decisions: [decision],
        renderer: { distanceM: allowed ? 0.5 : 0 },
      };
    },
  };
  const frames = [];
  const downloads = [];
  const window = {};
  const context = vm.createContext({
    document, window,
    matchMedia: () => ({ matches: reducedMotion }),
    requestAnimationFrame: callback => frames.push(callback),
    fetch: async () => ({ ok: true, json: async () => structuredClone(evidence) }),
    structuredClone, Blob,
    URL: {
      createObjectURL: value => { downloads.push(value); return 'blob:synthetic-test-download'; },
      revokeObjectURL() {},
    },
    setTimeout: callback => callback(),
    console,
  });
  const module = new vm.SourceTextModule(app, { context });
  await module.link(specifier => {
    assert.ok(['./engine.js', './scene.js'].includes(specifier), 'Unexpected app dependency');
    const name = specifier === './engine.js' ? 'createEngine' : 'createScene';
    return new vm.SyntheticModule([name], function () {
      this.setExport(name, async () => name === 'createEngine' ? engine : scene);
    }, { context });
  });
  await module.evaluate();
  return { get, cases, languages, frames, window, sceneEvents, downloads };
}

// Positive authorization first, then a failure must invalidate the old result.
const failure = await harness({ reducedMotion: false, failTamper: true });
assert.equal(failure.window.robotShieldDemo.getState().allowed, true);
failure.get('download-evidence').click();
assert.equal(failure.downloads.length, 1, 'Positive result must be exportable');
failure.cases.find(element => element.dataset.case === 'tamper').click();
assert.equal(failure.window.robotShieldDemo.getState().ready, false);
assert.equal(failure.window.robotShieldDemo.getEvidence(), null);
assert.equal(failure.get('download-evidence').disabled, true);
assert.equal(failure.get('scene-badge').textContent, 'NOT VERIFIED');
failure.get('download-evidence').click();
assert.equal(failure.downloads.length, 1, 'Failure must not export a stale allowed result');

// Translation re-renders the panel; it must not restore an old authorization.
failure.languages[1].click();
assert.equal(failure.window.robotShieldDemo.getEvidence(), null);
assert.equal(failure.get('scene-badge').textContent, 'NÃO VERIFICADO');
assert.equal(failure.get('download-evidence').disabled, true);
failure.get('download-evidence').click();
assert.equal(failure.downloads.length, 1);

// Reduced motion keeps the robot static while the timed guide advances cards.
const reduced = await harness({ reducedMotion: true, failTamper: false });
reduced.get('tour-button').click();
for (let second = 1; second <= 45; second++) {
  const frame = reduced.frames.shift();
  assert.ok(frame, 'The guide must schedule its next lifecycle tick');
  frame(second * 1000);
}
assert.equal(reduced.window.robotShieldDemo.getState().caseId, 'telemetry');
assert.equal(reduced.window.robotShieldDemo.getState().touring, false);
assert.equal(reduced.window.robotShieldDemo.getState().running, false);
assert.ok(reduced.sceneEvents.filter(event => event[0] === 'progress').every(event => event[1] === 1));
assert.ok(reduced.sceneEvents.filter(event => event[0] === 'paused').every(event => event[1] === true));

console.log(JSON.stringify({
  scope: 'Actual app lifecycle with explicit DOM/verifier/scene fault-injection stubs; not browser or authorization validation',
  checks: {
    positiveResultExport: true,
    failureClearsPreviousAuthorization: true,
    failurePreventsStaleExport: true,
    languageChangePreservesFailure: true,
    reducedMotionGuideCompletes: true,
    reducedMotionSceneRemainsStatic: true,
  },
}));

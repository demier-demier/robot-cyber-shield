import * as THREE from './vendor/three.module.min.js';

// Original product-shot geometry and visualization only. Security decisions,
// permitted movement and illustrative distances are supplied by the caller.
export async function createScene(container) {
  const resources = new Set();
  const keep = x => (resources.add(x), x);
  const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  let reducedMotion = motionQuery.matches;
  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false, powerPreference: 'high-performance' });
  } catch {
    const fallback = document.createElement('div');
    fallback.className = 'scene-fallback';
    fallback.textContent = 'The 3D view needs WebGL. Security verification and evidence remain available.';
    container.append(fallback);
    return { available: false, setMode() {}, setProgress() {}, setPaused() {}, reset() {}, resize() {}, dispose() { fallback.remove(); } };
  }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.65));
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.05;
  renderer.shadowMap.enabled = true;
  renderer.shadowMap.type = THREE.PCFSoftShadowMap;
  const canvas = renderer.domElement;
  canvas.style.cssText = 'width:100%;height:100%;display:block;';
  canvas.setAttribute('role', 'img');
  canvas.setAttribute('aria-label', 'Industrial mobile robot and a diagrammatic authorization boundary. Requests travel toward the boundary; unauthorized requests stop before reaching the robot.');
  container.append(canvas);

  const scene = new THREE.Scene();
  scene.background = new THREE.Color('#0d1217');
  scene.fog = new THREE.Fog('#0d1217', 8, 22);
  const camera = new THREE.PerspectiveCamera(28, 1, 0.08, 40);
  const look = new THREE.Vector3(-0.1, 0.28, 0);
  camera.position.set(4.15, 2.55, 6.1);
  camera.lookAt(look);

  // A procedurally built photographic light tent provides meaningful PBR
  // reflections without a downloaded HDR image or an external asset license.
  const envScene = new THREE.Scene();
  envScene.background = new THREE.Color('#111820');
  const envResources = [];
  const envPanel = (size, position, intensity, color, rotation = [0, 0, 0]) => {
    const geometry = new THREE.PlaneGeometry(...size);
    const material = new THREE.MeshBasicMaterial({ color, side: THREE.DoubleSide });
    material.color.multiplyScalar(intensity);
    const mesh = new THREE.Mesh(geometry, material);
    mesh.position.set(...position); mesh.rotation.set(...rotation);
    envScene.add(mesh); envResources.push(geometry, material);
  };
  envPanel([5, 3], [-3, 4, 3], 5, '#f7eddb', [0.35, -0.6, 0]);
  envPanel([0.8, 5], [4, 2, -2], 7, '#cae5f1', [0, Math.PI / 2, 0]);
  envPanel([5, 1], [0, 5, -2], 4, '#ffffff', [Math.PI / 2, 0, 0]);
  envPanel([2, 3], [1, 1, 4], 0.75, '#9eb6c5', [0, Math.PI, 0]);
  const pmrem = new THREE.PMREMGenerator(renderer);
  const environment = keep(pmrem.fromScene(envScene, 0.035, 0.1, 30));
  scene.environment = environment.texture;
  scene.environmentIntensity = 0.68;
  envResources.forEach(x => x.dispose()); pmrem.dispose();

  const material = (color, opts = {}) => keep(new THREE.MeshStandardMaterial({ color, metalness: 0.15, roughness: 0.48, ...opts }));
  const M = {
    ivory: keep(new THREE.MeshPhysicalMaterial({ color: '#d9e1dd', metalness: 0.24, roughness: 0.28, clearcoat: 0.45, clearcoatRoughness: 0.25 })),
    graphite: material('#192128', { metalness: 0.68, roughness: 0.32 }),
    graphiteSoft: material('#232c33', { metalness: 0.35, roughness: 0.52 }),
    aluminum: material('#a7b7bd', { metalness: 0.92, roughness: 0.27 }),
    darkSteel: material('#48555c', { metalness: 0.89, roughness: 0.32 }),
    tire: material('#111518', { metalness: 0.02, roughness: 0.91 }),
    tread: material('#1b2022', { metalness: 0.02, roughness: 0.87 }),
    black: material('#070c10', { metalness: 0.25, roughness: 0.28 }),
    amber: material('#d4942c', { metalness: 0.3, roughness: 0.34 }),
    glass: keep(new THREE.MeshPhysicalMaterial({ color: '#173d4c', metalness: 0.38, roughness: 0.075, clearcoat: 1, clearcoatRoughness: 0.05 })),
    rubber: material('#11181c', { metalness: 0.03, roughness: 0.78 }),
    red: material('#a02e2a', { roughness: 0.3 }),
    indicator: material('#d7e4da', { emissive: '#a5ceb4', emissiveIntensity: 0.35, roughness: 0.2 }),
  };
  const addMesh = (parent, geometry, mat, position, rotation = [0, 0, 0], shadow = true) => {
    const mesh = new THREE.Mesh(geometry, mat);
    mesh.position.set(...position); mesh.rotation.set(...rotation);
    mesh.castShadow = shadow; mesh.receiveShadow = true; parent.add(mesh);
    return mesh;
  };
  const box = (parent, size, pos, mat, rot, shadow = true) => addMesh(parent, keep(new THREE.BoxGeometry(...size)), mat, pos, rot, shadow);
  const cylinder = (parent, radius, height, pos, mat, rot = [0, 0, 0], segments = 40) => addMesh(parent, keep(new THREE.CylinderGeometry(radius, radius, height, segments)), mat, pos, rot);
  const torus = (parent, radius, tube, pos, mat, rot = [0, 0, 0]) => addMesh(parent, keep(new THREE.TorusGeometry(radius, tube, 10, 40)), mat, pos, rot);
  function plate(parent, width, depth, height, radius, pos, mat, bevel = 0.015) {
    const shape = new THREE.Shape();
    const x = -width / 2, y = -depth / 2, r = radius;
    shape.moveTo(x + r, y); shape.lineTo(x + width - r, y);
    shape.quadraticCurveTo(x + width, y, x + width, y + r);
    shape.lineTo(x + width, y + depth - r); shape.quadraticCurveTo(x + width, y + depth, x + width - r, y + depth);
    shape.lineTo(x + r, y + depth); shape.quadraticCurveTo(x, y + depth, x, y + depth - r);
    shape.lineTo(x, y + r); shape.quadraticCurveTo(x, y, x + r, y); shape.closePath();
    return addMesh(parent, keep(new THREE.ExtrudeGeometry(shape, { depth: height, steps: 1, curveSegments: 10, bevelEnabled: true, bevelSegments: 3, bevelSize: bevel, bevelThickness: bevel })), mat, pos, [-Math.PI / 2, 0, 0]);
  }
  const boltGeometry = keep(new THREE.CylinderGeometry(0.016, 0.016, 0.008, 6));
  function bolt(parent, pos, rot = [0, 0, 0]) { return addMesh(parent, boltGeometry, M.aluminum, pos, rot, false); }
  function decal(parent, text, pos, width, height = 0.10, color = '#bbc9ce', rotation = [0, 0, 0]) {
    const c = document.createElement('canvas'); c.width = 1024; c.height = 128;
    const ctx = c.getContext('2d');
    ctx.fillStyle = color; ctx.font = '600 65px Arial, sans-serif'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.fillText(text, 512, 64);
    const tex = keep(new THREE.CanvasTexture(c)); tex.colorSpace = THREE.SRGBColorSpace;
    return addMesh(parent, keep(new THREE.PlaneGeometry(width, height)), keep(new THREE.MeshBasicMaterial({ map: tex, transparent: true, depthWrite: false, polygonOffset: true, polygonOffsetFactor: -1, toneMapped: false })), pos, rotation, false);
  }

  scene.add(new THREE.AmbientLight('#9bb1bf', 0.22));
  const key = new THREE.DirectionalLight('#ffe8ca', 4.6); key.position.set(-3, 6, 4.2); key.castShadow = true;
  key.shadow.mapSize.set(2048, 2048); key.shadow.camera.left = -4; key.shadow.camera.right = 4;
  key.shadow.camera.top = 4; key.shadow.camera.bottom = -4; key.shadow.camera.near = 0.1; key.shadow.camera.far = 18;
  key.shadow.normalBias = 0.015; key.shadow.bias = -0.0001; scene.add(key);
  const rim = new THREE.DirectionalLight('#a7d4e9', 3.4); rim.position.set(2.5, 3.5, -3.2); scene.add(rim);
  const front = new THREE.DirectionalLight('#d2e1e8', 1.0); front.position.set(1, 1.5, 5); scene.add(front);
  const warm = new THREE.PointLight('#dca953', 4, 5); warm.position.set(-1.4, 0.5, -1.8); scene.add(warm);

  // Subtle original procedural concrete, no tiled sci-fi grid or warehouse props.
  const noiseCanvas = document.createElement('canvas'); noiseCanvas.width = noiseCanvas.height = 256;
  const nctx = noiseCanvas.getContext('2d'); const noise = nctx.createImageData(256, 256);
  let seed = 839;
  for (let i = 0; i < noise.data.length; i += 4) {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    const v = 126 + (seed >>> 28) - 8; noise.data.set([v, v, v, 255], i);
  }
  nctx.putImageData(noise, 0, 0);
  const concrete = keep(new THREE.CanvasTexture(noiseCanvas)); concrete.wrapS = concrete.wrapT = THREE.RepeatWrapping; concrete.repeat.set(12, 12);
  const floorMat = material('#182127', { metalness: 0.15, roughness: 0.69, bumpMap: concrete, bumpScale: 0.012 });
  const floor = addMesh(scene, keep(new THREE.PlaneGeometry(32, 32)), floorMat, [0, -0.005, 0], [-Math.PI / 2, 0, 0], false);
  floor.receiveShadow = true;
  box(scene, [12, 0.008, 0.009], [0, 0.001, -1.55], material('#4c5557', { roughness: 0.9 }), undefined, false);
  // Far architectural planes only: enough depth without shrinking the product.
  box(scene, [8, 3.5, 0.22], [0, 1.75, -5.8], material('#10191f', { roughness: 0.9 }), undefined, false);
  box(scene, [0.06, 3.5, 0.12], [-2.8, 1.75, -5.62], M.darkSteel, undefined, false);
  box(scene, [0.06, 3.5, 0.12], [2.8, 1.75, -5.62], M.darkSteel, undefined, false);

  const robot = new THREE.Group(); scene.add(robot);
  const robotStartX = 0.38; robot.position.x = robotStartX;
  // Low stance and separate undercarriage/shell/deck parts make the assembly legible.
  plate(robot, 1.80, 1.09, 0.16, 0.18, [0, 0.24, 0], M.graphite, 0.022);
  plate(robot, 1.72, 1.045, 0.19, 0.16, [0, 0.397, 0], M.ivory, 0.024);
  plate(robot, 1.61, 0.97, 0.026, 0.13, [-0.01, 0.606, 0], M.graphiteSoft, 0.010);
  plate(robot, 1.48, 0.85, 0.025, 0.10, [-0.02, 0.65, 0], M.aluminum, 0.008);
  // Nose fascia recessed between two protective corner covers.
  box(robot, [0.048, 0.14, 0.75], [0.873, 0.47, 0], M.black);
  box(robot, [0.052, 0.033, 0.48], [0.899, 0.488, 0], M.indicator);
  box(robot, [0.07, 0.11, 0.96], [0.915, 0.29, 0], M.rubber);
  for (const z of [-0.37, 0.37]) {
    box(robot, [0.063, 0.14, 0.10], [0.902, 0.445, z], M.graphite);
    cylinder(robot, 0.027, 0.011, [0.94, 0.448, z], M.glass, [0, 0, Math.PI / 2], 32);
  }
  // Rubber seam protects every edge while preserving the shell's panel breaks.
  for (const z of [-0.543, 0.543]) {
    box(robot, [1.32, 0.025, 0.016], [-0.04, 0.399, z], M.rubber);
    box(robot, [0.46, 0.095, 0.025], [-0.37, 0.503, z], M.graphiteSoft);
    for (let i = 0; i < 7; i++) box(robot, [0.018, 0.066, 0.012], [-0.55 + i * 0.058, 0.501, z * 1.03], M.black, undefined, false);
    for (const x of [-0.68, -0.04, 0.64]) bolt(robot, [x, 0.524, z * 1.02], [Math.PI / 2, 0, 0]);
  }
  // Four independent wheels, hard rims, lug bolts and deep all-around tread.
  const wheels = [];
  for (const x of [-0.59, 0.59]) for (const z of [-0.61, 0.61]) {
    const wheel = new THREE.Group(); wheel.position.set(x, 0.245, z); robot.add(wheel); wheels.push(wheel);
    cylinder(wheel, 0.24, 0.19, [0, 0, 0], M.tire, [Math.PI / 2, 0, 0], 48);
    torus(wheel, 0.195, 0.025, [0, 0, Math.sign(z) * 0.098], M.tread);
    cylinder(wheel, 0.135, 0.20, [0, 0, 0], M.darkSteel, [Math.PI / 2, 0, 0], 40);
    cylinder(wheel, 0.087, 0.212, [0, 0, 0], M.aluminum, [Math.PI / 2, 0, 0], 32);
    cylinder(wheel, 0.038, 0.219, [0, 0, 0], M.graphite, [Math.PI / 2, 0, 0], 24);
    for (let n = 0; n < 6; n++) {
      const a = n * Math.PI / 3;
      bolt(wheel, [Math.cos(a) * 0.105, Math.sin(a) * 0.105, Math.sign(z) * 0.109], [Math.PI / 2, 0, 0]);
    }
    for (let n = 0; n < 32; n++) {
      const a = n * Math.PI * 2 / 32;
      box(wheel, [0.032, 0.015, 0.188], [Math.sin(a) * 0.239, Math.cos(a) * 0.239, 0], M.tread, [0, 0, -a], false);
    }
  }
  // Recessed payload bay, machined rails and removable upper service cover.
  for (const z of [-0.29, 0.29]) {
    box(robot, [1.15, 0.035, 0.045], [-0.08, 0.70, z], M.graphite);
    for (const x of [-0.54, -0.12, 0.40]) bolt(robot, [x, 0.723, z]);
  }
  plate(robot, 0.64, 0.48, 0.035, 0.055, [-0.31, 0.718, 0], M.graphiteSoft, 0.009);
  for (let n = 0; n < 9; n++) box(robot, [0.022, 0.007, 0.27], [-0.55 + n * 0.055, 0.765, 0], M.black, undefined, false);
  for (const x of [-0.60, -0.01]) for (const z of [-0.205, 0.205]) bolt(robot, [x, 0.765, z]);

  // Twin-channel optical head with a stiff low mast, anodized bezel and real
  // lens construction: housing, dark aperture, glass, internal pupil, glint.
  plate(robot, 0.30, 0.34, 0.045, 0.035, [0.43, 0.70, 0], M.darkSteel, 0.008);
  box(robot, [0.085, 0.37, 0.105], [0.43, 0.92, 0], M.graphite);
  box(robot, [0.04, 0.32, 0.04], [0.37, 0.91, -0.07], M.aluminum);
  const optics = new THREE.Group(); optics.position.set(0.44, 1.13, 0); robot.add(optics);
  plate(optics, 0.28, 0.61, 0.17, 0.055, [0, -0.07, 0], M.ivory, 0.015);
  box(optics, [0.03, 0.14, 0.51], [0.161, 0.025, 0], M.graphite);
  const opticsAccent = [];
  for (const z of [-0.145, 0.145]) {
    cylinder(optics, 0.065, 0.043, [0.183, 0.028, z], M.black, [0, 0, Math.PI / 2], 40);
    torus(optics, 0.058, 0.009, [0.211, 0.028, z], M.aluminum, [0, Math.PI / 2, 0]);
    const lens = cylinder(optics, 0.048, 0.01, [0.217, 0.028, z], M.glass, [0, 0, Math.PI / 2], 40); opticsAccent.push(lens);
    cylinder(optics, 0.020, 0.012, [0.224, 0.028, z], M.black, [0, 0, Math.PI / 2], 32);
    const glint = material('#9ed7e6', { emissive: '#468b9d', emissiveIntensity: 0.5, metalness: 0.65, roughness: 0.1 });
    cylinder(optics, 0.008, 0.014, [0.226, 0.043, z - 0.018], glint, [0, 0, Math.PI / 2], 16);
  }
  const cable = new THREE.CatmullRomCurve3([new THREE.Vector3(0.31, 0.74, -0.10), new THREE.Vector3(0.25, 0.87, -0.13), new THREE.Vector3(0.30, 1.08, -0.13), new THREE.Vector3(0.39, 1.12, -0.10)]);
  addMesh(robot, keep(new THREE.TubeGeometry(cable, 24, 0.013, 8, false)), M.rubber, [0, 0, 0]);
  // Rear lidar has an optical band, screw ring and subtle engraved top cap.
  cylinder(robot, 0.125, 0.052, [-0.55, 0.744, 0], M.darkSteel);
  cylinder(robot, 0.113, 0.11, [-0.55, 0.824, 0], M.glass);
  cylinder(robot, 0.128, 0.018, [-0.55, 0.886, 0], M.aluminum);
  cylinder(robot, 0.098, 0.008, [-0.55, 0.899, 0], M.graphite);
  for (let n = 0; n < 6; n++) bolt(robot, [-0.55 + Math.cos(n * Math.PI / 3) * 0.112, 0.903, Math.sin(n * Math.PI / 3) * 0.112]);
  // Physical local controls are decorative, not an emergency-stop simulation.
  cylinder(robot, 0.051, 0.018, [-0.43, 0.707, 0.35], M.amber, undefined, 24);
  cylinder(robot, 0.031, 0.034, [-0.43, 0.731, 0.35], M.red, undefined, 24);
  cylinder(robot, 0.025, 0.075, [-0.68, 0.738, -0.31], M.amber, undefined, 24);
  const sidePlate = box(robot, [0.65, 0.105, 0.013], [0.28, 0.501, 0.556], M.graphiteSoft);
  decal(robot, 'RCS  /  ROVER 01', [0.28, 0.505, 0.566], 0.53, 0.050, '#d6ded9');
  sidePlate.name = 'original_product_identifier';
  decal(robot, 'AUTONOMOUS MOBILE PLATFORM', [0.03, 0.31, 0.566], 0.72, 0.032, '#83959d');
  for (const x of [-0.74, 0.74]) for (const z of [-0.39, 0.39]) bolt(robot, [x, 0.647, z]);

  // Contact occlusion is a conventional illustrative shadow, not a physics field.
  const shadowCanvas = document.createElement('canvas'); shadowCanvas.width = shadowCanvas.height = 256;
  const sctx = shadowCanvas.getContext('2d'); const grad = sctx.createRadialGradient(128, 128, 20, 128, 128, 128);
  grad.addColorStop(0, 'rgba(0,0,0,.68)'); grad.addColorStop(0.6, 'rgba(0,0,0,.34)'); grad.addColorStop(1, 'rgba(0,0,0,0)');
  sctx.fillStyle = grad; sctx.fillRect(0, 0, 256, 256);
  const shadowTexture = keep(new THREE.CanvasTexture(shadowCanvas));
  const contact = addMesh(scene, keep(new THREE.PlaneGeometry(2.8, 1.9)), keep(new THREE.MeshBasicMaterial({ map: shadowTexture, transparent: true, depthWrite: false })), [robotStartX, 0.002, 0], [-Math.PI / 2, 0, 0], false);

  // The authorization boundary is a restrained wire diagram beside the real
  // robot, not an imaginary physical shield. No cartoon icons or cube packets.
  const boundary = new THREE.Group(); scene.add(boundary);
  const gate = new THREE.Vector3(-0.96, 0.53, 0.57);
  const source = new THREE.Vector3(-2.0, 0.53, 0.57);
  const boundaryLineMaterial = keep(new THREE.LineBasicMaterial({ color: '#728690', transparent: true, opacity: 0.74 }));
  const boundaryPoints = [new THREE.Vector3(gate.x, 0.15, 0.38), new THREE.Vector3(gate.x, 1.02, 0.38), new THREE.Vector3(gate.x, 1.02, 0.73), new THREE.Vector3(gate.x, 0.15, 0.73)];
  const gateWire = new THREE.Line(keep(new THREE.BufferGeometry().setFromPoints(boundaryPoints)), boundaryLineMaterial); boundary.add(gateWire);
  const boundaryWireMaterial = keep(new THREE.MeshBasicMaterial({ color: '#9aaeb5', transparent: true, opacity: 0.8 }));
  const verticalWire = addMesh(boundary, keep(new THREE.CylinderGeometry(0.004, 0.004, 0.88, 8)), boundaryWireMaterial, [gate.x, 0.59, gate.z], undefined, false);
  verticalWire.name = 'diagrammatic_authorization_boundary';
  for (const y of [0.15, 1.02]) {
    const tick = new THREE.Line(keep(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(gate.x - 0.035, y, 0.57), new THREE.Vector3(gate.x + 0.035, y, 0.57)])), boundaryLineMaterial); boundary.add(tick);
  }
  const routeMaterial = keep(new THREE.LineBasicMaterial({ color: '#6d7e86', transparent: true, opacity: 0.28 }));
  const route = new THREE.Line(keep(new THREE.BufferGeometry().setFromPoints([source, gate, new THREE.Vector3(robotStartX - 0.80, 0.53, 0.57)])), routeMaterial); scene.add(route);
  const pulseMaterial = keep(new THREE.LineBasicMaterial({ color: '#e8b36c', transparent: true, opacity: 0.95 }));
  const pulse = new THREE.Line(keep(new THREE.BufferGeometry().setFromPoints([source, source, source])), pulseMaterial); scene.add(pulse);
  const pulseHeadMaterial = keep(new THREE.MeshBasicMaterial({ color: '#efbd77' }));
  const pulseHead = addMesh(scene, keep(new THREE.SphereGeometry(0.022, 14, 10)), pulseHeadMaterial, source.toArray(), undefined, false);
  const pulseBodyMaterial = keep(new THREE.MeshBasicMaterial({ color: '#efbd77', transparent: true, opacity: 0.95 }));
  const pulseBodyGeometry = keep(new THREE.CylinderGeometry(0.008, 0.008, 1, 8));
  const pulseBodies = [0, 1].map(() => addMesh(scene, pulseBodyGeometry, pulseBodyMaterial, [0, 0, 0], undefined, false));
  const gateHitMaterial = keep(new THREE.MeshBasicMaterial({ color: '#dc6753', transparent: true, opacity: 0, depthWrite: false, side: THREE.DoubleSide }));
  const gateHit = addMesh(scene, keep(new THREE.PlaneGeometry(0.20, 0.62)), gateHitMaterial, gate.toArray(), [0, Math.PI / 2, 0], false);
  const sensorHighlightMaterial = keep(new THREE.LineBasicMaterial({ color: '#b6d9e9', transparent: true, opacity: 0 }));
  const sensorHighlight = new THREE.LineSegments(keep(new THREE.EdgesGeometry(new THREE.BoxGeometry(0.04, 0.18, 0.56))), sensorHighlightMaterial);
  sensorHighlight.position.set(0.177, 0.022, 0); optics.add(sensorHighlight);
  // A subdued motion witness on the floor, not an invented physical trajectory.
  const motionLine = new THREE.Line(keep(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(robotStartX, 0.012, 0.79), new THREE.Vector3(robotStartX, 0.012, 0.79)])), keep(new THREE.LineBasicMaterial({ color: '#b7c9c4', transparent: true, opacity: 0.4 }))); scene.add(motionLine);

  // Two unobtrusive HTML labels keep the diagram readable at every pixel ratio.
  // Root may setLanguage(), otherwise the document language is respected.
  const annotations = [source, new THREE.Vector3(gate.x, 1.10, gate.z)].map((point, index) => {
    const el = document.createElement('div');
    el.className = `scene-annotation scene-annotation-${index ? 'guard' : 'origin'}`;
    el.style.cssText = 'position:absolute;z-index:2;pointer-events:none;transform:translate(-50%,-100%);padding:7px 9px;border:1px solid #82939a55;border-radius:3px;background:#111b21d9;color:#cbd8d9;font:600 9px/1.1 system-ui,sans-serif;letter-spacing:.12em;white-space:nowrap;';
    el.setAttribute('aria-hidden', 'true'); container.append(el);
    return { point: point.clone().add(new THREE.Vector3(0, index ? 0 : 0.10, 0)), el };
  });

  let mode = { kind: 'normal', allowed: true, movementAllowed: true };
  let progress = 0, paused = true, disposed = false, frame = 0, width = 0, height = 0, language = null;
  const clamp = x => Math.max(0, Math.min(1, x));
  const ease = x => { x = clamp(x); return x * x * (3 - 2 * x); };
  const vector = new THREE.Vector3();
  function update() {
    const p = clamp(progress), cameraMode = mode.kind === 'camera', telemetry = mode.kind === 'telemetry', replay = mode.kind === 'replay';
    const motionAllowed = mode.movementAllowed ?? (mode.allowed || cameraMode || telemetry);
    const d = Number.isFinite(mode.distanceM) ? Math.max(0, Math.min(3, mode.distanceM)) : replay ? 0.05 : 0.725;
    const moveP = replay ? ease(p / 0.36) : ease((p - 0.28) / 0.72);
    const meters = (replay || motionAllowed) ? d * moveP : 0;
    robot.position.x = robotStartX + meters; contact.position.x = robot.position.x;
    for (const wheel of wheels) wheel.rotation.z = -meters / 0.24;
    motionLine.geometry.setFromPoints([new THREE.Vector3(robotStartX, 0.012, 0.79), new THREE.Vector3(robot.position.x, 0.012, 0.79)]);
    const blocked = !mode.allowed && (!replay || p >= 0.43);
    const color = blocked ? '#df735f' : '#e4c28a';
    pulseMaterial.color.set(color); pulseHeadMaterial.color.set(color); pulseBodyMaterial.color.set(color);
    boundaryLineMaterial.color.set(blocked && p >= 0.3 ? '#d96b58' : '#71878f');
    boundaryWireMaterial.color.set(blocked && p >= 0.3 ? '#db7b67' : '#9aaeb5');
    boundaryLineMaterial.opacity = p >= 0.3 ? 0.95 : 0.60;
    const receiver = cameraMode || telemetry ? new THREE.Vector3(robot.position.x + 0.64, 1.158, 0.145) : new THREE.Vector3(robot.position.x - 0.79, 0.53, 0.57);
    route.geometry.setFromPoints([source, gate, receiver]);
    const maxProgress = blocked ? 0.42 : 1;
    let t = reducedMotion ? maxProgress : Math.min(maxProgress, p * 1.8);
    if (replay && p >= 0.43) t = Math.min(0.42, (p - 0.43) * 2.8);
    const sample = fraction => {
      if (fraction <= 0.42) return new THREE.Vector3().lerpVectors(source, gate, fraction / 0.42);
      return new THREE.Vector3().lerpVectors(gate, receiver, (fraction - 0.42) / 0.58);
    };
    const tip = sample(t), tail = sample(Math.max(0, t - 0.22));
    const middle = t > 0.42 && t - 0.22 < 0.42 ? gate : tail.clone().lerp(tip, 0.5);
    pulse.geometry.setFromPoints([tail, middle, tip]);
    const parts = t > 0.42 && t - 0.22 < 0.42 ? [[tail, gate], [gate, tip]] : [[tail, tip]];
    pulseBodies.forEach((body, index) => {
      const part = parts[index];
      body.visible = Boolean(part);
      if (!part) return;
      const direction = part[1].clone().sub(part[0]);
      body.position.copy(part[0]).addScaledVector(direction, 0.5);
      body.scale.y = Math.max(0.0001, direction.length());
      body.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), direction.normalize());
    });
    pulseHead.position.copy(tip);
    const active = mode.kind !== 'idle' && p > 0.01 && p < 0.94;
    pulse.visible = pulseHead.visible = active;
    pulseBodies.forEach((body, index) => { body.visible = active && Boolean(parts[index]); });
    pulseMaterial.opacity = p > 0.75 ? Math.max(0, (0.94 - p) / 0.19) : 0.98;
    pulseBodyMaterial.opacity = pulseMaterial.opacity;
    const contactMoment = blocked && t >= 0.419 && active;
    gateHitMaterial.opacity = contactMoment ? (reducedMotion || paused ? 0.14 : 0.10 + 0.13 * Math.sin(p * 32) ** 2) : 0;
    sensorHighlightMaterial.opacity = cameraMode ? 0.55 : telemetry ? 0.28 : 0;
    // Incoming camera reads do not turn off optics or stop a permitted mission.
    boundary.visible = route.visible = mode.kind !== 'idle';
    const portuguese = (language || document.documentElement.lang || 'en').startsWith('pt');
    annotations.forEach(({ point, el }, index) => {
      const projected = point.clone().project(camera);
      el.style.left = `${Math.max(50, Math.min(width - 50, (projected.x * 0.5 + 0.5) * width))}px`;
      el.style.top = `${Math.max(54, Math.min(height - 106, (-projected.y * 0.5 + 0.5) * height))}px`;
      el.style.display = mode.kind === 'idle' ? 'none' : 'block';
      el.textContent = index ? (portuguese ? 'PROTEÇÃO' : 'GUARD') : (portuguese ? 'PEDIDO' : 'REQUEST');
    });
    vector.set(robot.position.x - robotStartX, 0, 0);
  }
  function render() { if (!disposed) { update(); renderer.render(scene, camera); } }
  function schedule() { if (!disposed && !document.hidden && !frame) frame = requestAnimationFrame(() => { frame = 0; render(); }); }
  function resize() {
    if (disposed) return;
    const bounds = container.getBoundingClientRect();
    const w = Math.max(1, Math.round(bounds.width)), h = Math.max(1, Math.round(bounds.height || 500));
    if (w === width && h === height) return;
    width = w; height = h; camera.aspect = w / h;
    // Product framing is based on a controlled horizontal span. The robot is
    // intentionally large, rather than shrinking into a wide warehouse view.
    const horizontalSpan = Math.max(w < 560 ? 4.25 : 4.7, camera.aspect * 2.10);
    const distance = camera.position.distanceTo(look);
    camera.fov = THREE.MathUtils.radToDeg(2 * Math.atan(horizontalSpan / (2 * distance * camera.aspect)));
    camera.updateProjectionMatrix(); renderer.setSize(w, h, false); render();
  }
  const observer = new ResizeObserver(resize); observer.observe(container);
  const onVisibility = () => { if (!document.hidden) render(); };
  const onMotion = () => { reducedMotion = motionQuery.matches; schedule(); };
  document.addEventListener('visibilitychange', onVisibility); motionQuery.addEventListener('change', onMotion);
  resize(); render();
  return {
    available: true,
    setMode(value) { mode = { ...mode, ...value }; progress = 0; schedule(); },
    setProgress(value) { progress = Number.isFinite(value) ? clamp(value) : 0; schedule(); },
    setPaused(value) { paused = Boolean(value); schedule(); },
    setLanguage(value) { language = typeof value === 'string' ? value : null; schedule(); },
    reset() { progress = 0; paused = true; schedule(); },
    resize,
    dispose() {
      disposed = true; observer.disconnect(); document.removeEventListener('visibilitychange', onVisibility); motionQuery.removeEventListener('change', onMotion);
      if (frame) cancelAnimationFrame(frame);
      annotations.forEach(({ el }) => el.remove());
      for (const r of resources) r.dispose?.(); renderer.dispose(); canvas.remove();
    },
  };
}

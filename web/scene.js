import * as THREE from './vendor/three.module.min.js';

// An original visual test cell. This renderer never decides authorization:
// the caller supplies the verifier result and controls the presentation clock.
// Distances illustrate the observed synthetic actuator cases, not real hardware.
export async function createScene(container) {
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const resources = new Set();
  const keep = value => { resources.add(value); return value; };
  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false, powerPreference: 'low-power' });
  } catch {
    const fallback = document.createElement('div');
    fallback.className = 'scene-fallback';
    fallback.textContent = 'The 3D view needs WebGL. The security decisions and evidence below still work.';
    container.append(fallback);
    return { available: false, setMode() {}, setProgress() {}, reset() {}, resize() {}, setPaused() {}, dispose() { fallback.remove(); } };
  }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.6));
  renderer.shadowMap.enabled = true;
  renderer.shadowMap.type = THREE.PCFSoftShadowMap;
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.14;
  renderer.domElement.setAttribute('aria-label', 'Illustrated robot security test cell. A mobile robot receives a permitted command or a blocked request.');
  renderer.domElement.setAttribute('role', 'img');
  renderer.domElement.style.cssText = 'width:100%;height:100%;display:block;outline:none;';
  container.append(renderer.domElement);

  const scene = new THREE.Scene();
  scene.background = new THREE.Color('#182b37');
  scene.fog = new THREE.Fog('#182b37', 10, 23);
  const camera = new THREE.PerspectiveCamera(34, 1, 0.1, 50);
  const lookAt = new THREE.Vector3(-0.18, 0.42, 0.0);
  camera.position.set(5.2, 4.15, 5.9);
  camera.lookAt(lookAt);

  const mat = (color, opts = {}) => keep(new THREE.MeshStandardMaterial({ color, roughness: 0.62, metalness: 0.08, ...opts }));
  const C = {
    floor: mat('#3a515d', { roughness: 0.9 }),
    seam: mat('#2b414b', { roughness: 1 }),
    chalk: mat('#b3c2c5', { roughness: 1 }),
    graphite: mat('#182f3b', { roughness: 0.48, metalness: 0.36 }),
    steel: mat('#617783', { roughness: 0.3, metalness: 0.75 }),
    aluminum: mat('#bac7ce', { roughness: 0.28, metalness: 0.62 }),
    white: mat('#eff1e9', { roughness: 0.36, metalness: 0.15 }),
    black: mat('#15232a', { roughness: 0.93 }),
    amber: mat('#f3b736', { roughness: 0.33, metalness: 0.12 }),
    darkAmber: mat('#ba791f'),
    lens: mat('#1d4853', { roughness: 0.13, metalness: 0.72 }),
    red: mat('#c84f48', { emissive: '#ac2928', emissiveIntensity: 0.22 }),
    green: mat('#218d78', { emissive: '#197966', emissiveIntensity: 0.18 }),
    plastic: mat('#a8b1aa', { roughness: 0.85 }),
  };

  const box = (parent, size, position, material, options = {}) => {
    const mesh = new THREE.Mesh(keep(new THREE.BoxGeometry(...size)), material);
    mesh.position.set(...position);
    mesh.castShadow = options.shadow !== false;
    mesh.receiveShadow = true;
    parent.add(mesh);
    return mesh;
  };
  const cylinder = (parent, radius, height, position, material, segments = 32) => {
    const mesh = new THREE.Mesh(keep(new THREE.CylinderGeometry(radius, radius, height, segments)), material);
    mesh.position.set(...position);
    mesh.castShadow = true; mesh.receiveShadow = true;
    parent.add(mesh);
    return mesh;
  };
  function roundedPlate(parent, width, length, height, radius, position, material) {
    const shape = new THREE.Shape();
    const x = -width / 2, y = -length / 2;
    shape.moveTo(x + radius, y);
    shape.lineTo(x + width - radius, y);
    shape.quadraticCurveTo(x + width, y, x + width, y + radius);
    shape.lineTo(x + width, y + length - radius);
    shape.quadraticCurveTo(x + width, y + length, x + width - radius, y + length);
    shape.lineTo(x + radius, y + length);
    shape.quadraticCurveTo(x, y + length, x, y + length - radius);
    shape.lineTo(x, y + radius);
    shape.quadraticCurveTo(x, y, x + radius, y);
    const geometry = keep(new THREE.ExtrudeGeometry(shape, { depth: height, bevelEnabled: true, bevelSegments: 2, steps: 1, bevelSize: 0.012, bevelThickness: 0.012, curveSegments: 5 }));
    const mesh = new THREE.Mesh(geometry, material);
    mesh.rotation.x = -Math.PI / 2;
    mesh.position.set(...position);
    mesh.castShadow = true; mesh.receiveShadow = true;
    parent.add(mesh);
    return mesh;
  }
  function label(parent, text, position, width, options = {}) {
    const canvas = document.createElement('canvas');
    canvas.width = 768; canvas.height = 144;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    if (options.background) {
      ctx.fillStyle = options.background;
      ctx.fillRect(0, 0, canvas.width, canvas.height);
    }
    ctx.fillStyle = options.color || '#4d6570';
    ctx.textBaseline = 'middle'; ctx.textAlign = 'center';
    ctx.font = `600 ${options.fontSize || 54}px system-ui, sans-serif`;
    ctx.fillText(text, 384, 72);
    const texture = keep(new THREE.CanvasTexture(canvas));
    texture.colorSpace = THREE.SRGBColorSpace;
    const material = keep(new THREE.MeshBasicMaterial({ map: texture, transparent: true, depthWrite: false, side: THREE.DoubleSide, toneMapped: false }));
    const mesh = new THREE.Mesh(keep(new THREE.PlaneGeometry(width, width * 144 / 768)), material);
    mesh.position.set(...position);
    if (options.floor) mesh.rotation.x = -Math.PI / 2;
    else mesh.quaternion.copy(camera.quaternion);
    parent.add(mesh);
    return mesh;
  }

  scene.add(new THREE.HemisphereLight('#e0eff6', '#263b44', 2.2));
  const sun = new THREE.DirectionalLight('#fff9e8', 4.1);
  sun.position.set(-2.5, 7.5, 4.5);
  sun.castShadow = true;
  sun.shadow.mapSize.set(1536, 1536);
  sun.shadow.camera.left = -6; sun.shadow.camera.right = 6;
  sun.shadow.camera.top = 5; sun.shadow.camera.bottom = -5;
  sun.shadow.camera.near = 0.5; sun.shadow.camera.far = 20;
  sun.shadow.normalBias = 0.025;
  scene.add(sun);
  const fill = new THREE.DirectionalLight('#c5e4f2', 1.1);
  fill.position.set(4, 3, -4); scene.add(fill);

  // Slab, expansion joints, marking tape and a restrained industrial backdrop.
  box(scene, [16, 0.16, 12], [0, -0.1, 0], C.floor, { shadow: false });
  for (let x = -6; x <= 6; x += 2) box(scene, [0.013, 0.003, 10], [x, -0.014, 0], C.seam, { shadow: false });
  for (let z = -4; z <= 4; z += 2) box(scene, [14, 0.003, 0.013], [0, -0.014, z], C.seam, { shadow: false });
  for (const z of [-1.22, 1.22]) box(scene, [4.7, 0.006, 0.055], [0.15, 0.002, z], C.chalk, { shadow: false });
  for (const x of [-2.2, 2.5]) box(scene, [0.055, 0.006, 2.44], [x, 0.002, 0], C.chalk, { shadow: false });
  for (let i = 0; i < 12; i++) {
    const strip = box(scene, [0.17, 0.008, 0.17], [-1.85 + i * 0.34, 0.008, 1.18], i % 2 ? C.graphite : C.amber, { shadow: false });
    strip.rotation.y = Math.PI / 4;
  }
  label(scene, 'ROBOT TEST CELL  /  01', [0.2, 0.015, 1.62], 2.5, { floor: true, color: '#aac1ca', fontSize: 48 });
  // A dashed mission route helps a small measured displacement remain legible.
  for (let i = 0; i < 14; i++) box(scene, [0.11, 0.006, 0.016], [-0.75 + i * 0.18, 0.012, 0], C.chalk, { shadow: false });
  const dock = new THREE.Group(); dock.position.set(2.22, 0, 0); scene.add(dock);
  box(dock, [0.16, 0.62, 0.86], [0, 0.31, 0], C.graphite);
  box(dock, [0.18, 0.12, 0.42], [-0.025, 0.48, 0], C.white);
  box(dock, [0.18, 0.05, 0.16], [-0.035, 0.48, 0], C.green);
  box(dock, [0.5, 0.07, 1.02], [-0.12, 0.03, 0], C.steel);
  label(scene, 'DOCK', [2.05, 0.02, 0.84], 0.6, { floor: true, color: '#aac1ca', fontSize: 64 });

  const rack = new THREE.Group(); rack.position.set(-0.3, 0, -2.85); scene.add(rack);
  const rackMaterial = mat('#4f6a77', { metalness: 0.5, roughness: 0.5 });
  for (const x of [-1.8, 0, 1.8]) for (const z of [-0.37, 0.37]) box(rack, [0.065, 1.8, 0.065], [x, 0.9, z], rackMaterial);
  for (const y of [0.14, 0.82, 1.48]) {
    box(rack, [3.65, 0.07, 0.82], [0, y, 0], rackMaterial);
    for (let i = 0; i < 4; i++) {
      const crate = new THREE.Group(); crate.position.set(-1.35 + i * 0.88, y + 0.24, 0); rack.add(crate);
      box(crate, [0.62, 0.39, 0.59], [0, 0, 0], i % 2 ? C.plastic : C.white);
      box(crate, [0.48, 0.05, 0.61], [0, 0.08, 0], rackMaterial);
      box(crate, [0.18, 0.1, 0.008], [0, -0.055, 0.302], C.chalk);
    }
  }
  // A service cabinet, cable conduit and safety bollards provide scene scale.
  box(scene, [0.62, 1.47, 0.5], [3.4, 0.735, -2.4], C.white);
  box(scene, [0.56, 1.32, 0.018], [3.4, 0.75, -2.14], C.aluminum);
  box(scene, [0.025, 0.2, 0.035], [3.61, 0.8, -2.11], C.graphite);
  for (const x of [-2.55, 2.8]) {
    cylinder(scene, 0.067, 0.72, [x, 0.36, -1.5], C.amber, 20);
    cylinder(scene, 0.071, 0.13, [x, 0.5, -1.5], C.graphite, 20);
    box(scene, [0.26, 0.035, 0.26], [x, 0.015, -1.5], C.steel);
  }

  // Original autonomous mobile robot: suspension, tread, service panels,
  // bumper, optics and a removable inspection payload.
  const robot = new THREE.Group(); scene.add(robot);
  const robotStart = -0.55;
  robot.position.set(robotStart, 0, 0);
  roundedPlate(robot, 1.42, 0.91, 0.20, 0.13, [0, 0.25, 0], C.graphite);
  roundedPlate(robot, 1.29, 0.85, 0.20, 0.12, [0, 0.43, 0], C.white);
  roundedPlate(robot, 1.15, 0.75, 0.038, 0.08, [0, 0.638, 0], C.aluminum);
  const wheels = [];
  for (const x of [-0.43, 0.43]) for (const z of [-0.49, 0.49]) {
    const wheel = new THREE.Group(); wheel.position.set(x, 0.22, z); robot.add(wheel); wheels.push(wheel);
    const tyre = cylinder(wheel, 0.218, 0.14, [0, 0, 0], C.black, 32); tyre.rotation.x = Math.PI / 2;
    const hub = cylinder(wheel, 0.112, 0.15, [0, 0, 0], C.aluminum, 24); hub.rotation.x = Math.PI / 2;
    const cap = cylinder(wheel, 0.043, 0.16, [0, 0, 0], C.graphite, 24); cap.rotation.x = Math.PI / 2;
    for (let i = 0; i < 14; i++) {
      const angle = i * Math.PI * 2 / 14;
      const tread = box(wheel, [0.065, 0.023, 0.147], [Math.sin(angle) * 0.213, Math.cos(angle) * 0.213, 0], C.black, { shadow: false });
      tread.rotation.z = -angle;
    }
  }
  for (const z of [-0.434, 0.434]) {
    box(robot, [0.73, 0.11, 0.018], [-0.05, 0.53, z], C.graphite);
    for (let i = 0; i < 8; i++) box(robot, [0.015, 0.07, 0.008], [-0.32 + i * 0.075, 0.53, z * 1.025], C.steel, { shadow: false });
    for (const x of [-0.48, 0.45]) {
      const screw = cylinder(robot, 0.014, 0.018, [x, 0.54, z * 1.03], C.steel, 8); screw.rotation.x = Math.PI / 2;
    }
  }
  // Front rubber bumper and two actual-looking sensor windows.
  box(robot, [0.09, 0.09, 0.65], [0.71, 0.29, 0], C.black);
  for (const z of [-0.24, 0.24]) {
    box(robot, [0.035, 0.072, 0.15], [0.662, 0.52, z], C.graphite);
    box(robot, [0.039, 0.035, 0.097], [0.665, 0.526, z], C.lens);
  }
  const statusMaterial = mat('#2c9f80', { emissive: '#2c9f80', emissiveIntensity: 0.7 });
  box(robot, [0.06, 0.029, 0.34], [0.704, 0.40, 0], statusMaterial);
  box(robot, [0.06, 0.029, 0.28], [-0.709, 0.40, 0], C.red);
  // Mounting rails and a sensor mast, with strain-relieved cable.
  for (const z of [-0.23, 0.23]) box(robot, [0.78, 0.045, 0.055], [-0.04, 0.7, z], C.graphite);
  roundedPlate(robot, 0.47, 0.53, 0.07, 0.04, [-0.18, 0.72, 0], C.amber);
  box(robot, [0.075, 0.67, 0.075], [-0.18, 1.08, 0], C.graphite);
  box(robot, [0.12, 0.24, 0.12], [-0.18, 0.87, 0], C.steel);
  const cableCurve = new THREE.CatmullRomCurve3([
    new THREE.Vector3(-0.24, 0.79, -0.09), new THREE.Vector3(-0.31, 1.05, -0.08),
    new THREE.Vector3(-0.27, 1.35, -0.05), new THREE.Vector3(-0.12, 1.40, -0.02),
  ]);
  const cable = new THREE.Mesh(keep(new THREE.TubeGeometry(cableCurve, 16, 0.014, 7, false)), C.black); robot.add(cable);
  roundedPlate(robot, 0.36, 0.27, 0.14, 0.04, [-0.11, 1.37, 0], C.white);
  box(robot, [0.027, 0.106, 0.23], [0.082, 1.445, 0], C.graphite);
  for (const z of [-0.066, 0.066]) {
    const lens = cylinder(robot, 0.035, 0.027, [0.10, 1.445, z], C.lens, 24); lens.rotation.z = Math.PI / 2;
    const surround = new THREE.Mesh(keep(new THREE.TorusGeometry(0.038, 0.006, 6, 24)), C.aluminum);
    surround.position.set(0.116, 1.445, z); surround.rotation.y = Math.PI / 2; robot.add(surround);
  }
  cylinder(robot, 0.107, 0.09, [0.38, 0.72, 0], C.graphite, 32);
  const lidar = cylinder(robot, 0.098, 0.07, [0.38, 0.8, 0], C.lens, 32);
  cylinder(robot, 0.107, 0.019, [0.38, 0.844, 0], C.aluminum, 32);
  const beaconMaterial = mat('#f3b736', { emissive: '#d58f15', emissiveIntensity: 0.7 });
  cylinder(robot, 0.034, 0.07, [-0.5, 0.72, 0.25], beaconMaterial, 16);
  cylinder(robot, 0.04, 0.014, [-0.5, 0.68, 0.25], C.graphite, 16);
  const emergencyBase = cylinder(robot, 0.05, 0.025, [-0.45, 0.697, -0.22], C.amber, 20);
  cylinder(robot, 0.029, 0.035, [-0.45, 0.725, -0.22], C.red, 20);
  emergencyBase.name = 'illustrative_emergency_button_not_functional';
  // Matte identifier plate, avoids oversized floating HUDs on the robot.
  label(robot, 'RCS  /  01', [0.03, 0.455, 0.455], 0.43, { color: '#eef4ed', fontSize: 70 });

  // Clear visual request path and authorization boundary. The panel is a
  // diagrammatic overlay in the world; it is not a claimed physical shield.
  const signal = new THREE.Group(); scene.add(signal);
  const gatewayX = -1.6;
  const shieldShape = new THREE.Shape();
  shieldShape.moveTo(0, 0.42); shieldShape.lineTo(0.27, 0.30);
  shieldShape.lineTo(0.25, -0.05); shieldShape.quadraticCurveTo(0.20, -0.28, 0, -0.43);
  shieldShape.quadraticCurveTo(-0.20, -0.28, -0.25, -0.05);
  shieldShape.lineTo(-0.27, 0.30); shieldShape.closePath();
  const shieldMaterial = keep(new THREE.MeshBasicMaterial({ color: '#268e7b', transparent: true, opacity: 0.91, side: THREE.DoubleSide, depthWrite: false }));
  const shield = new THREE.Mesh(keep(new THREE.ShapeGeometry(shieldShape)), shieldMaterial);
  shield.position.set(gatewayX, 1.0, 0.33); shield.quaternion.copy(camera.quaternion); signal.add(shield);
  const checkPoints = [new THREE.Vector3(-0.12, 0.02, 0.014), new THREE.Vector3(-0.025, -0.07, 0.014), new THREE.Vector3(0.14, 0.12, 0.014)];
  const check = new THREE.Line(keep(new THREE.BufferGeometry().setFromPoints(checkPoints)), keep(new THREE.LineBasicMaterial({ color: '#ffffff' })));
  shield.add(check);
  const gatewayLabel = label(signal, 'POLICY CHECK', [gatewayX, 0.46, 0.35], 1.17, { color: '#365965', background: '#e6efed', fontSize: 49 });
  const blockedMark = label(signal, 'BLOCKED', [gatewayX, 1.62, 0.35], 0.95, { color: '#a82c27', background: '#f4e8e2', fontSize: 58 });
  blockedMark.visible = false;
  const pathMaterial = keep(new THREE.LineDashedMaterial({ color: '#558b8b', dashSize: 0.09, gapSize: 0.06, transparent: true, opacity: 0.75 }));
  const pathPoints = [new THREE.Vector3(-3.1, 1.02, 0.33), new THREE.Vector3(gatewayX, 1.02, 0.33), new THREE.Vector3(-0.6, 1.02, 0.33)];
  const requestPath = new THREE.Line(keep(new THREE.BufferGeometry().setFromPoints(pathPoints)), pathMaterial);
  requestPath.computeLineDistances(); signal.add(requestPath);
  label(signal, 'REQUEST', [-2.92, 1.28, 0.32], 0.85, { color: '#c4d6dd', fontSize: 52 });
  const packetMaterial = mat('#248f7b', { emissive: '#248f7b', emissiveIntensity: 0.55 });
  const packetGeometry = keep(new THREE.BoxGeometry(0.075, 0.075, 0.075));
  const packets = Array.from({ length: 4 }, () => { const p = new THREE.Mesh(packetGeometry, packetMaterial); signal.add(p); return p; });
  const rejectionRing = new THREE.Mesh(keep(new THREE.RingGeometry(0.34, 0.355, 48)), keep(new THREE.MeshBasicMaterial({ color: '#bd5147', transparent: true, opacity: 0.0, side: THREE.DoubleSide, depthWrite: false })));
  rejectionRing.position.copy(shield.position); rejectionRing.position.z += 0.012; rejectionRing.quaternion.copy(camera.quaternion); signal.add(rejectionRing);

  // Narrow sensor field of view: imagery is deliberately synthetic.
  const fovGeometry = keep(new THREE.BufferGeometry().setFromPoints([
    new THREE.Vector3(0.1, 1.45, 0), new THREE.Vector3(1.3, 0.02, -0.72),
    new THREE.Vector3(1.3, 0.02, 0.72), new THREE.Vector3(0.1, 1.45, 0),
  ]));
  const fovMaterial = keep(new THREE.LineBasicMaterial({ color: '#638e9c', transparent: true, opacity: 0.25 }));
  const fov = new THREE.Line(fovGeometry, fovMaterial); robot.add(fov);

  let mode = { kind: 'normal', allowed: true };
  let progress = 0, paused = true, frame = 0, disposed = false;
  let viewWidth = 0, viewHeight = 0;
  function update() {
    const p = Math.max(0, Math.min(1, progress));
    const dataMode = mode.kind === 'camera' || mode.kind === 'telemetry';
    const isReplay = mode.kind === 'replay';
    const acceptedMotion = mode.allowed || dataMode;
    const fallbackDistance = isReplay ? 0.05 : 0.725;
    const distance = Number.isFinite(mode.distanceM) ? Math.max(0, Math.min(3, mode.distanceM)) : fallbackDistance;
    const meters = isReplay ? distance * Math.min(1, p * 4) : acceptedMotion ? distance * p : 0;
    robot.position.x = robotStart + meters;
    for (const wheel of wheels) wheel.rotation.z = -meters / 0.218;
    // A replay case contains one initial permitted delivery, followed by a
    // duplicate rejection. Show those two phases instead of implying that a
    // rejected request caused the initial short movement.
    const blocked = !mode.allowed && mode.kind !== 'idle' && (!isReplay || p >= 0.25);
    const color = blocked ? '#bb5148' : '#268e7b';
    shieldMaterial.color.set(blocked ? '#537b77' : '#268e7b');
    packetMaterial.color.set(color); packetMaterial.emissive.set(color);
    pathMaterial.color.set(color);
    blockedMark.visible = blocked;
    statusMaterial.color.set('#2c9f80');
    statusMaterial.emissive.set('#2c9f80');
    fovMaterial.opacity = dataMode ? 0.56 : 0.19;
    const active = !paused && p > 0 && p < 1;
    beaconMaterial.emissiveIntensity = active && !reducedMotion ? 0.35 + 0.45 * Math.sin(p * 36) ** 2 : 0.35;
    lidar.rotation.y = p * 8;
    const endX = blocked ? gatewayX - 0.3 : robot.position.x - 0.12;
    requestPath.geometry.setFromPoints([
      new THREE.Vector3(-3.1, 1.02, 0.33), new THREE.Vector3(gatewayX, 1.02, 0.33),
      new THREE.Vector3(blocked ? gatewayX : endX, 1.02, 0.33),
    ]);
    requestPath.computeLineDistances();
    for (let i = 0; i < packets.length; i++) {
      const packet = packets[i];
      const phase = reducedMotion ? i / 4 : (p * 5 + i / 4) % 1;
      packet.position.set(-3.1 + phase * (endX + 3.1), 1.02, 0.33);
      packet.visible = mode.kind !== 'idle' && p > 0.015 && p < 0.995;
      packet.rotation.set(0.2, phase * 2, 0.2);
    }
    rejectionRing.material.opacity = blocked && active ? (reducedMotion ? 0.3 : 0.12 + 0.35 * Math.sin(p * 22) ** 2) : 0;
    rejectionRing.scale.setScalar(1 + (reducedMotion ? 0 : Math.sin(p * 22) ** 2 * 0.13));
    gatewayLabel.visible = mode.kind !== 'idle';
    signal.visible = mode.kind !== 'idle';
  }
  function render() {
    if (disposed) return;
    update();
    renderer.render(scene, camera);
  }
  function resize() {
    if (disposed) return;
    const rect = container.getBoundingClientRect();
    const width = Math.max(1, Math.round(rect.width));
    const height = Math.max(1, Math.round(rect.height || 430));
    if (width === viewWidth && height === viewHeight) return;
    viewWidth = width; viewHeight = height;
    camera.aspect = width / height;
    // Keep the complete request-to-robot story in narrow layouts.
    camera.fov = width < 540 ? 48 : width < 760 ? 40 : 34;
    camera.updateProjectionMatrix();
    renderer.setSize(width, height, false);
    render();
  }
  const observer = new ResizeObserver(resize); observer.observe(container);
  const visibility = () => { if (!document.hidden) render(); };
  document.addEventListener('visibilitychange', visibility);
  function schedule() {
    if (disposed || document.hidden) return;
    if (!frame) frame = requestAnimationFrame(() => { frame = 0; render(); });
  }
  resize(); render();
  return {
    available: true,
    setMode(value) { mode = { ...mode, ...value }; progress = 0; schedule(); },
    setProgress(value) { progress = Number.isFinite(value) ? Math.max(0, Math.min(1, value)) : 0; schedule(); },
    setPaused(value) { paused = Boolean(value); schedule(); },
    reset() { progress = 0; paused = true; schedule(); },
    resize,
    dispose() {
      disposed = true; observer.disconnect(); document.removeEventListener('visibilitychange', visibility);
      if (frame) cancelAnimationFrame(frame);
      for (const resource of resources) resource.dispose?.();
      renderer.dispose(); renderer.domElement.remove();
    },
  };
}

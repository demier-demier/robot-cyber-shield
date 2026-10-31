# Visual security demonstration

The browser experience explains one boundary at a time: the request, the guard's decision and the effect on robot movement or data access. The visual robot and environment are illustrative. They are not a camera recording, physics benchmark or physical robot deployment.

## Two kinds of evidence

| Mode | What executes | What it establishes |
| --- | --- | --- |
| Interactive Rust verifier | WebAssembly verification of original signed demo requests, using a recorded logical mission clock and browser memory for the demo session | The implemented verifier's decision for that input; simulated motion follows the result |
| Recorded ROS 2 evidence | Playback of reviewed observations from the native Linux ROS 2 / SROS2 lab | What the native middleware and software driver actually did in that recorded test |

The browser does not start ROS 2, control a physical robot, authenticate a real camera or isolate operating-system processes. A browser session is not a trusted deployment boundary. SQLite-backed durability and native DDS enforcement remain properties of the native implementation and its separate tests.

Mission time in the interactive verifier is logical test time, not the visitor's wall clock. That permits deterministic signature, expiry and replay demonstrations without publishing private signing keys or making a demo unexpectedly expire. Browser reset is a new in-memory demo session, not persistence across native service restarts.

The browser adapter uses `BrowserGuard` over `MemoryGuard`. The native SQLite guard and the browser guard call the shared Rust `verify_request` and `admission_denial` functions. JavaScript selects fixtures and presents returned decisions; it does not independently implement an allow/deny rule. The engine reports a visible error if the actual result disagrees with a fixture's acceptance check.

The camera-access scenario is specifically **recorded ROS 2 evidence**. DDS denied creation of the raw-data reader for the restricted analytics identity. The controlled native sensor published a synthetic marker, not an actual camera recording. Any stylized camera view shown in the visual scene is an illustration; no captured image is disclosed or represented as proof.

## Recorded evidence provenance

Source code: `76024ea1044288f67a45c400c26e64b8e11152be`.

Native run: [ROS 2 security integration, 41248935977](https://github.com/demier-demier/robot-cyber-shield/actions/runs/41248935977).

`web/data/ros-evidence.json` contains six independently initialized cases and 44 passed native checks. It preserves all original synthetic driver samples, with each case's timestamps normalized to its first observed sample. It does not invent intermediate measured samples. A renderer may interpolate these observations to make playback smooth, but an interpolated frame is not an additional measurement.

The main seven-second visual scenes are explanatory animations, not timestamp-exact replay. The camera scene illustrates the native case's observed displacement while preserving its denial and positive-control facts. Live WASM movement uses a separate illustrative integration of the commands actually admitted in the browser and their leases. Its distances must not be presented as the historical ROS measurements. The downloaded decision identifies its live or recorded source.

The native cases reset state between tests. The authorized baseline reached approximately 0.725 m, the replay case moved approximately 0.050 m once, and signed negative cases remained at zero. Switching between cases is not a single continuous robot mission. The camera-denial test occurred alongside an authorized baseline: blocking the reader did not require stopping permitted robot operation.

The recorded camera test includes its positive control: the permitted raw reader received 29 samples and the permitted minimal-data reader received 29; the forbidden raw-data reader failed endpoint creation. The unsecured listener started but received zero raw samples. These observations prevent an absent sensor or entirely broken network from being presented as successful protection.

## Regenerate the reviewed projection

Download the `ros2-native-observations` artifact from the linked run to a local directory. Use its `ros2` subdirectory as the source:

```sh
python3 scripts/build_demo_evidence.py \
  --source /path/to/observations/ros2 \
  --source-commit 76024ea1044288f67a45c400c26e64b8e11152be \
  --ci-url https://github.com/demier-demier/robot-cyber-shield/actions/runs/41248935977
python3 -m unittest discover -s tests -p 'test_demo_evidence.py' -v
```

CI artifacts have finite retention. The reviewed projection and the original compact summary remain committed. A new native run can generate new observations, but must use its own commit and run URL; scheduling-dependent counts must not be copied from the historical run.

The projector requires successful authorized controls, all six cases, native DDS permission error evidence and bounded monotonic timelines. It exports only allowlisted fields. File hashes bind its source artifact bytes; no keystores, grants, raw frame/audio contents, absolute timestamps or private filesystem paths are copied. Hashes establish which bytes were projected, not independent source authenticity.

## Presentation guidance

- Start with permitted operation so the viewer sees the robot and data stream working.
- Alter a signed command to show why the guard rejects it before movement.
- Use the camera scenario to explain that controlling motion and reading data are separate permissions.
- Replay a command to show that a previously valid request cannot extend its authority indefinitely.
- Keep the mode label visible. Share the native evidence link when making claims about ROS enforcement.

The demonstration should remain intelligible without source-code knowledge. Detailed protocol fields and test reports belong in the evidence view, while the main presentation states the requested action, decision and observable effect.

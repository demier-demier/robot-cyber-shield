# Observed validation

Measured on 2026-10-31. These results concern original synthetic robot inputs, native middleware and a software actuator. They do not establish physical robot safety, general intrusion-detection accuracy, real-time control or deployment readiness.

## Native application boundary

On the authoring Apple Silicon Mac:

- 24 Rust tests passed: 21 security behavior tests and 3 executable CLI tests.
- The independent CLI workflow passed 11 checks using fresh authority/holder keys and persistent SQLite state across new service processes.
- Four subprocess IPC checks passed: a working framed-response control, malformed JSON, duplicate response lines and timeout. The fault peers are explicitly synthetic; the bridge implementation under test is real.
- Rustfmt, Clippy with warnings denied, and Python Ruff checks passed.

The initial [cross-platform native workflow](https://github.com/demier-demier/robot-cyber-shield/actions/runs/41248542898) passed on Linux, macOS and Windows. Unix permission/symlink tests apply only to Unix; POSIX pipe tests are skipped on Windows. A Windows core result is not a claim that the ROS bridge runs on Windows.

## Real ROS 2 integration

The initial [ROS 2 run](https://github.com/demier-demier/robot-cyber-shield/actions/runs/41248542899) passed six scenarios and 38 checks at commit `2d4e5a0b8e0b6c203f836483170dbedda8b130ed`.

It also exposed a delivery limitation: the baseline planner sent 33 commands while the guard and driver received/executed 19. The harness initially used a fixed discovery delay. That observation prompted a change to wait for a matched subscriber and require equality between published, authorized and executed commands in the baseline. This is a test acceptance criterion, not a general reliable-delivery guarantee or an application acknowledgement protocol.

The native DDS logs explicitly reported denied creation of a writer on `rt/robot/cmd_vel` and a reader on `rt/robot/sensors/raw` because those topics were absent from the roles' allow rules. Missing enclave credentials prevented initialization under `Enforce`. An unsecured listener started but received no raw samples while the authorized guard received 30. Those are concrete endpoint observations; no transport packet capture was performed.

The first replay case admitted one command, then denied 32 further deliveries: 13 due to replay and 19 because the same request had become stale. Both reasons are retained instead of attributing every rejection to replay.

## Recorded ROS 2 baseline used by the visual demo

Code revision: `76024ea1044288f67a45c400c26e64b8e11152be`.

- [Native CI](https://github.com/demier-demier/robot-cyber-shield/actions/runs/41248936038): passed on Linux, macOS and Windows, including the 11-check executable workflow on each. IPC fault tests passed on POSIX and were explicitly skipped on Windows.
- [ROS 2 CI](https://github.com/demier-demier/robot-cyber-shield/actions/runs/41248935977): six scenarios and **44/44 acceptance checks passed**.
- Checked-in reviewed evidence: [native Mac workflow](results/native-macos-2026-10-31.json), [ROS observations](results/ros2-2026-10-31.json), [resolved ROS package versions](results/ros2-packages-2026-10-31.txt).

| ROS scenario | Commands published | Allowed by guard | Accepted by driver | Guard denials |
| --- | ---: | ---: | ---: | ---: |
| Authorized baseline after discovery | 19 | 19 | 19 | 0 |
| Repeated envelope | 33 | 1 | 1 | 32 |
| Wrong holder proof | 31 | 0 | 0 | 31 |
| Stale signed command | 33 | 0 | 0 | 33 |
| Signed command above speed limit | 33 | 0 | 0 | 33 |
| Command altered after signing | 32 | 0 | 0 | 32 |

The baseline waited 14 discovery cycles before its first publication. All 19 commands then reached both guard and driver in this run. The synthetic position advanced approximately 0.725 m and commanded velocity returned to zero after lease expiry. This measures software fixture behavior, not physical stopping distance.

Both authenticated forbidden endpoints were rejected by DDS. The unsecured raw-data listener received zero messages, while the authorized raw reader and the permitted minimal-data observer received samples. Every exported sample matched the six-field allowlist. Four signed attack scenarios produced zero admitted commands and zero synthetic displacement; their exact rejection reasons are recorded in the report.

## Browser verifier and visual demonstration

The browser and native service now share the Rust signature-verification and admission-policy functions. Local validation passed 26 Rust tests, including native/memory parity, and 11 Python tests on POSIX. The emitted WASM passed eight scenarios, 36 decisions and five invalid-clock checks. Six app lifecycle checks exercise failure cleanup and reduced-motion playback using explicitly stubbed DOM/scene peers; those are separate from real WASM verification.

Actual browser interaction exercised all nine selectable scenes, the evidence view, English/Portuguese switching and compact layouts. The published five-scene guide completed. A downloaded tamper decision contained `invalid_request_signature`, no forwarded command and zero illustrative movement. The focused visual revision was tested by [browser CI](https://github.com/demier-demier/robot-cyber-shield/actions/runs/41251616126) and [native CI](https://github.com/demier-demier/robot-cyber-shield/actions/runs/41251616114) at `7718b6300e475ecdbb103b38f045661cbacb9382`.

WASM's permitted sequence has 28 admitted commands and an illustrative lease-bounded displacement of 0.7375 m. A repeated request permits only the first lease (0.0625 m); the other command attacks produce zero displacement. These are kinematic integrations of verified commands, not physical measurements. Camera access explicitly uses the recorded native run above, not live DDS in a browser. See [the visual demo's evidence boundary](VISUAL-DEMO.md).

### Observed native reliability failure

A later [ROS 2 run](https://github.com/demier-demier/robot-cyber-shield/actions/runs/41251407457) failed its authorized-delivery baseline: 32 commands were published, 31 admitted by the guard and 30 accepted by the software driver. All 32 reached the guard; one was rejected by its rate limit. The driver rejected one additional command, but that run did not retain its rejection reason. Lease expiry or ordering is not established as the cause.

All negative security checks and the other five scenarios passed in that run. No unauthorized command was executed. This is nevertheless a real permitted-work reliability failure, and prevents a claim of zero valid-command loss. The revision changed only visual assets/documentation, not the native guard or ROS harness. Further work must expose the driver's rejection reason and validate the positive-control scheduling without weakening the security policy or the baseline assertion. A later passing rerun would not erase this observation.

## Reproduce and interpret

```sh
cargo test --locked
cargo build --locked
python3 scripts/check_local_workflow.py --output artifacts/native-workflow.json
python3 -m unittest discover -s tests -p 'test_*.py' -v
# On Linux with ROS 2 Jazzy and SROS2 installed:
cargo build --locked --release
bash scripts/run_ros2_lab.sh
```

ROS reports retain actual package versions. Current apt packages and the container tag can change; compare environment inventories between runs. Counts, discovery wait and movement values can vary with scheduling. The assertions check intended behavior rather than fixed timing or a claimed performance score.

All role keys share one controlled test host. Runtime host isolation, key provisioning/rotation, unavailable or restored replay state, overload behavior, model/firmware integrity and hardware-specific actuator acknowledgement/stopping remain deployment work. The local decision journal is bounded and administrator-modifiable; it is not an externally anchored forensic log.

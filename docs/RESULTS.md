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

## Current validated revision

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

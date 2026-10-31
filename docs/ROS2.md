# Native ROS 2 security lab

This integration uses ROS 2 Jazzy, Fast DDS, SROS2 identities and permissions, and the actual Rust enforcement process. The robot endpoint is a **synthetic kinematic actuator**, not a hardware controller or a certified safety component. No ROS API is mocked in the integration runner.

The authoring Mac does not have ROS 2 installed. Python syntax and Rust behavior can be checked there; native DDS outcomes must come from the Linux workflow or a local ROS 2 installation. Read the latest workflow's `ros2-native-observations` artifact before treating a scenario as passed. Configuring encryption is not packet-capture verification of encryption.

## Data flow

```text
planner process -- signed command --> /shield/requests ----+
                                                         |
driver process -- signed synthetic sensor --> /robot/sensors/raw
                                                         |
                                                     guard process
                                                         |
                                   persistent Rust JSONL daemon + SQLite
                                   authority grant + holder proof + replay
                                   bounds + age + telemetry projection
                                                         |
                           +-----------------------------+-------------------+
                           |                                                 |
                    /robot/cmd_vel                              /robot/telemetry/minimal
                           |                                                 |
                     driver process                                   analytics process
                     kinematic stub                                 allowlisted fields only
                     lease watchdog
                           |
                       /robot/state --> trusted test observer
```

Every role is a separate OS process with its own DDS enclave identity. The lab launches them under one OS account and stores ephemeral keys in a private temporary directory. That is **not** OS-level isolation from a process that can read another process's files. A deployment needs separate users/containers, per-role key mounts, and a protected authority. The test-only observer sees precise pose to verify effects; it is more privileged than analytics.

| Enclave | Application publish permission | Application subscribe permission |
| --- | --- | --- |
| `/shield/planner` | `/shield/requests` | None |
| `/shield/guard` | `/robot/cmd_vel`, `/robot/telemetry/minimal` | `/shield/requests`, `/robot/sensors/raw` |
| `/shield/driver` | `/robot/sensors/raw`, `/robot/state` | `/robot/cmd_vel` |
| `/shield/analytics` | None | `/robot/telemetry/minimal` |
| `/shield/observer` | None | `/robot/state`, `/robot/telemetry/minimal` |
| `/shield/outsider` | None | None |

All roles also receive narrow DDS graph infrastructure permissions (`ros_discovery_info` publish/subscribe and `rt/parameter_events` publish). ROS logging, parameter services and the type-description service are disabled. The policy has no application-topic wildcard grants. The `*` governance topic expression applies mandatory controls to every topic; it does not grant access.

## Enforcement boundaries

- SROS2 generates fresh CA and enclave certificates. The script replaces default permissions with per-role default-deny policies, validates them against SROS2's installed DDS XML schemas, signs them, and verifies the signatures.
- Governance rejects unauthenticated participants, enables join/read/write access checks, and configures discovery, liveliness, topic metadata and topic data protection as `ENCRYPT`. RTPS message protection is `SIGN`, matching the DDS layering rather than claiming every transport byte is encrypted.
- `ROS_SECURITY_ENABLE=true` and `ROS_SECURITY_STRATEGY=Enforce` are set for protected processes. A missing enclave must fail startup. The unsecured listener test deliberately uses `ROS_SECURITY_ENABLE=false` to prove that an external unsecured participant obtains no raw sensor samples while a positive authorized reader is active.
- DDS identity authorizes the transport topic. Application principal identity is independently checked by the Rust guard through the authority-signed grant and holder-signed request. A JSON `principal` field alone is not trusted.
- The guard forwards only a matching allowed Rust result. An IPC timeout, partial/malformed frame, process failure or invalid JSON poisons and terminates that Rust daemon instance. No future request can accidentally receive a delayed earlier decision.
- Allowed commands carry an absolute `valid_until_ms`. The driver checks robot/session, grant sequence, expiry and local velocity bounds. It stops when the lease expires. Replaying an output does not renew its lease. The driver caps retained grant sequence entries at 128 and fails closed at the cap; it is not a fleet lifecycle manager.
- Analytics receives only robot ID, operational status, battery percentage, and quantized position cells. Synthetic raw camera/audio/operator marker fields are removed by the Rust allowlist. Position quantization is data minimization, not a guarantee of anonymity.

## Reproduce

Use Ubuntu with ROS 2 Jazzy and a current stable Rust toolchain:

```bash
sudo apt-get update
sudo apt-get install ros-jazzy-sros2 ros-jazzy-rmw-fastrtps-cpp ros-jazzy-std-msgs build-essential pkg-config
cargo build --locked --release
bash scripts/run_ros2_lab.sh
```

The workflow runs these native tests in the official `ros:jazzy-ros-base` container and records installed package versions. The container tag and apt repository evolve; the package inventory is evidence of the resolved versions for each run, not an immutable image lock.

The runner uses loopback, domain 73, bounded process durations and per-process timeouts. Use a different unused domain (1–100) to run alongside other ROS systems. Existing evidence is never overwritten:

```bash
SHIELD_ROS2_OUTPUT=/tmp/shield-new-observations bash scripts/run_ros2_lab.sh --domain 74
# Short initial end-to-end check:
SHIELD_ROS2_OUTPUT=/tmp/shield-baseline bash scripts/run_ros2_lab.sh --cases baseline
```

No ROS daemon or physical robot is required. No network beyond the local DDS participants is targeted. The runner does not install packages or enable paid infrastructure itself.

## Acceptance criteria

| Scenario | Required native observation |
| --- | --- |
| Authorized mission | Signed commands reach Rust, actuator accepts them, observed position changes, then velocity returns to zero after the planner stops and the lease expires. |
| Replay | First signed envelope is allowed exactly once; repeated deliveries are denied and cannot keep the robot moving. |
| Wrong holder | A transplanted signature reaches Rust through the authorized planner topic and is denied; driver accepts zero commands and position remains unchanged. |
| Stale request | Correctly signed old timestamp is denied; zero actuator effects. This tests request age, not grant expiry. |
| Overspeed | Correctly signed command outside the grant/policy bounds is denied; zero actuator effects. |
| Post-signing tamper | An otherwise valid command is edited after signing, reaches Rust and is denied; zero actuator effects. |
| Unauthorized actuator publisher | Authenticated outsider initializes but native DDS rejects creation of its actuator publisher; its marked command is never executed. |
| Unauthorized raw subscriber | Analytics initializes, but native DDS rejects its raw sensor subscriber; its separately launched permitted minimal subscriber receives sanitized samples. |
| Missing credentials | `Enforce` refuses initialization of the missing enclave. |
| Unsecured subscriber | Native unsecured subscriber starts but receives zero raw samples while the authorized guard receives raw samples. |

Results include both successful controls and failed/denied cases. A negative test cannot pass merely because all processes failed or no sensor data existed. `summary.json` is true only when every selected scenario's acceptance checks pass.

Evidence contains bounded JSON observations, sanitized process logs, policy metadata and package versions. It excludes keystores, private keys, signed grants/envelopes, raw frame payloads and SQLite state. Ephemeral credentials are removed at the end of the run.

## Limits

This milestone does not measure physical stopping distance, actuator power isolation, malicious firmware, compromise of the trusted guard/driver, independent DDS implementations, transport packet contents, denial-of-service resilience, fleet-scale throughput, hardware-backed keys or functional safety. The 10 Hz stub uses host clocks and scheduling; it is not a real-time controller. Per-message CLI signing is deliberately easy to inspect and is not an optimized production signing path. The evidence is a native middleware/application integration test, not certification or a claim that robots cannot be hacked.

## Primary references

- [ROS 2 Jazzy security introduction, official documentation source](https://github.com/ros2/ros2_documentation/blob/jazzy/source/Tutorials/Advanced/Security/Introducing-ros2-security.rst)
- [ROS 2 Jazzy access controls, official documentation source](https://github.com/ros2/ros2_documentation/blob/jazzy/source/Tutorials/Advanced/Security/Access-Controls.rst)
- [SROS2 Jazzy governance defaults](https://github.com/ros2/sros2/blob/jazzy/sros2/sros2/policy/defaults/dds/governance.xml)
- [SROS2 keystore implementation](https://github.com/ros2/sros2/blob/jazzy/sros2/sros2/keystore/_keystore.py)
- [Jazzy rclpy node implementation](https://github.com/ros2/rclpy/blob/jazzy/rclpy/rclpy/node.py)

The policies, fixtures and endpoint scripts in this repository are original work. Referenced upstream source was used to verify APIs and policy semantics; it is not bundled here.

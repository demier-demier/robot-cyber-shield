# Robot Cyber Shield

**A command and data security boundary for ROS 2 robots.**

A navigation agent needs to move a robot. An analytics client needs its battery level. Neither permission should automatically grant access to its cameras, unlimited motion commands, or an old mission's credentials.

Robot Cyber Shield combines a Rust authorization service with real ROS 2 / SROS2 topic permissions. It checks a signed mission grant and a separate holder signature on each request, persists accepted sequences, and publishes only approved commands or explicitly minimized telemetry.

The repository includes executable integration tests. The ROS processes and cryptographic checks are real; the driver, motion and camera-like payloads are synthetic. Security decisions use deterministic verification, with no AI inference in the enforcement path.

## What the working boundary does

| Request | Enforcement |
| --- | --- |
| Authorized planner sends a fresh command | Check authority and holder signatures, robot/session/principal, speed limits and command lifetime; persist admission before forwarding |
| A command or grant is edited | Reject invalid proof, even if the sender can publish to the request topic |
| A valid command is replayed after restart | Reject the already consumed sequence using SQLite state |
| A mission grant is revoked | Reject subsequent requests using that grant |
| Another DDS participant publishes directly to the actuator | Deny through signed per-role DDS permissions |
| Analytics attempts to subscribe to the raw sensor topic | Deny raw access; allow the approved minimal telemetry topic |
| An authorized sensor sends camera/audio/operator data | Export only status, battery and coarse location cells; never forward arbitrary input fields |
| Commands stop arriving | The synthetic driver's software lease expires and its commanded velocity returns to zero |

Location coarsening is **data minimization, not anonymization**. A software lease is **not a certified emergency stop**. A compromised authorized host can defeat controls at its own trust boundary.

## Validated results

The [observed validation record](docs/RESULTS.md) includes 24 Rust tests on the Mac, 11 executable workflow checks on Linux/macOS/Windows, four POSIX IPC tests, and a real ROS 2 run with **44/44 checks passed**. In that run, all 19 authorized baseline commands reached the driver after discovery; all four signed attack scenarios produced zero actuator commands. The record also preserves the initial discovery/delivery limitation and its correction.

## Try the native workflow

Requires a current stable Rust toolchain and Python 3.9+; no ROS installation, cloud account, GPU, model API or purchased service is needed.

```sh
cargo build --locked
python3 scripts/check_local_workflow.py --output artifacts/native-workflow.json
cargo test --locked
```

The runner creates temporary authority/holder keys, issues original synthetic mission grants, invokes the actual native service, restarts it to check durable replay rejection, tests revocation and checks the exact exported telemetry fields. It deletes temporary keys and state on completion. The report contains observed decisions, not credentials or raw sensor samples.

## Exercise real ROS 2 security

See [the ROS 2 lab](docs/ROS2.md) for prerequisites and the runnable command. The Linux integration workflow starts real ROS 2 Jazzy processes using Fast DDS, temporary SROS2 identities and signed default-deny topic permissions. It connects the Rust service to the command and telemetry paths.

Successful authorized delivery is checked before relying on a negative result. A network discovery failure alone must never count as a successful security control. CI reports keep middleware observations separate from native authorization tests.

The lab generates security material at runtime. **Do not commit keystores or private keys.** Its shared test machine is a controlled fixture, not an example of production secret isolation.

## Components

```text
planner + holder key -- signed request --> guard + Rust service --> driver
                                             ^                       |
                                             |---- raw telemetry ----|
                                             |
                                             +-- minimal status --> analytics
```

- **Rust:** typed policy checks, Ed25519 signatures, bounded input, replay/revocation persistence and minimized output.
- **ROS 2 / Python:** native nodes, per-role DDS permissions, driver effect checks and integration orchestration.
- **SQLite:** admission state bound to the configured authority and mission policy. Accepted state commits before output; crashes can lose delivery, and are not treated as permission to replay.

The service also keeps a bounded local journal of the last 2,048 decisions: sequence ID, time, allow/deny reason and an input fingerprint. Accepted decisions commit atomically with replay state. The journal excludes raw sensor content, complete requests and credentials; it is not tamper-proof against an administrator of the host. The operator can inspect it with `robot-cyber-shield audit --state runtime/state.sqlite --limit 100`.

Read [architecture and acceptance criteria](docs/ARCHITECTURE.md), the [threat model](docs/THREAT-MODEL.md), and [source provenance](PROVENANCE.md).

## Operating boundaries

This milestone protects a defined command/data route. It does not secure a robot's firmware, boot chain, physical ports, models, training data, every ROS service/action, or a separate unguarded actuator route. It does not detect every intrusion or establish legal/regulatory compliance.

Runtime keys, issuer authority, policy, clock, OS isolation and state storage are trusted. Deleting or restoring old state can destroy replay protection; clock rollback and recovery need an operator procedure. State budgets deliberately fail closed instead of silently discarding revocations or replay history. Key lifecycle, hardware-in-the-loop tests, bounded load/latency evaluation and independent deployment review remain necessary before a physical deployment.

The next useful extension is integrity verification for robot assets and models, followed by a hardware adapter with measured command acknowledgements and independent stopping. Neither is represented as implemented here.

## License

Original code and fixtures: [MIT](LICENSE). External dependencies retain their own licenses.

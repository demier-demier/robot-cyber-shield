# Architecture and acceptance contract

The first milestone is a command and data-access boundary that can be exercised against ROS 2 middleware. The Rust authorization core also runs locally without a robot. It performs deterministic cryptographic and policy checks; it does not use an AI model to classify a command as safe.

## Two independent layers

```text
Operator authority                       Mission client
  signs a bounded grant ---------------> keeps holder private key
                                           signs each command
                                                   |
                                    /shield/requests (planner enclave)
                                                   |
                         +-------------------------v-------------------+
                         | Rust authorization core                     |
                         | authority signature + holder proof          |
                         | audience + role + session + time + limits    |
                         | persistent sequence / revocation state      |
                         +-------------------------+-------------------+
                                                   | accepted command only
                                             Gateway enclave
                                                   |
                                           /robot/cmd_vel
                                                   |
                                      Synthetic driver + lease expiry

Synthetic sensor --> /robot/sensors/raw --> guard enclave + Rust core
                                                 |
                                      explicit field minimization
                                                 |
                                      /robot/telemetry/minimal
                                                 |
                                          analytics enclave
```

The diagram describes the integration implemented by `ros2/lab_node.py`. Native execution of this graph requires the ROS lab; consult its run report for observed results. Separate component success is not evidence that an untested end-to-end connection works.

**Application authorization:** possession of the mission authority's public key allows the guard to verify grants. The holder key inside a grant authenticates request proof. A verified subject is a configured software principal. It is not a verified employee, an authenticated ROS enclave name, or evidence about the physical machine executing the request.

**Transport authorization:** DDS security certificates and signed permissions govern which participant can publish or subscribe on each allowed topic. This complements message signatures; neither replaces the other. The bridge must not trust a plaintext caller-supplied principal as identity, and its actuator publish permission must not be shared with clients.

The application proof signs a typed Rust value serialized as compact JSON, preceded by a versioned domain separator. Grant and request signatures use different domains; the request proof covers both the signed grant and operation-tagged request. This is the repository's protocol, not a claim to implement a general JSON canonicalization standard. External clients should use the supplied signer until an independent interoperable encoding specification and vectors are available.

## Native ROS role matrix

The exact generated matrix is defined in [`ros2/security_policy.py`](../ros2/security_policy.py). Every role has a separate `/shield/<role>` enclave; all other application topics are denied. Narrow middleware discovery/parameter-event permissions are also needed by the ROS runtime.

| Enclave role | Application publish | Application subscribe |
| --- | --- | --- |
| `planner` | `/shield/requests` | None |
| `guard` | `/robot/cmd_vel`, `/robot/telemetry/minimal` | `/shield/requests`, `/robot/sensors/raw` |
| `driver` | `/robot/sensors/raw`, `/robot/state` | `/robot/cmd_vel` |
| `analytics` | None | `/robot/telemetry/minimal` |
| `observer` | None | `/robot/state`, `/robot/telemetry/minimal` |
| `outsider` | None | None |

`observer` is privileged test instrumentation: `/robot/state` deliberately contains exact synthetic pose and actuator receipts so the runner can verify effects. It is not the privacy-restricted analytics role. A deployment must remove that diagnostic route or authorize it separately; the minimization claim applies to `analytics` on `/robot/telemetry/minimal`.

## Durable decision boundary

1. Parse a strictly defined request with bounded input sizes.
2. Verify the authority signature and holder proof using the expected version and domain separation.
3. Check the intended robot, principal, mission session, operation, validity window, freshness and configured numeric limits.
4. Read revocation/replay state and consume the admitted sequence and append the accepted decision journal entry in one database transaction.
5. Return an acceptance only after durable commit. The adapter forwards only accepted commands. Denials also attempt a journal append; a failed journal write returns a storage-failure denial.
6. On denial or storage failure, emit a bounded decision reason without echoing private input.

This is command admission with replay protection, not an exactly-once actuator protocol. A crash after step 4 and before delivery can lose an admitted command. Automatically retrying it with the same sequence must not make it execute twice. A later integration requiring execution confirmation needs robot-generated acknowledgements, idempotent operation IDs and recovery rules.

Persistent state is bound to policy and authority fingerprints. A policy/key change cannot silently reuse that state. It belongs to one configured robot/session trust boundary and a protected local directory. Backup restoration requires an explicit recovery procedure; accepting an old database can restore old replay state. SQLite durability does not defend against a privileged host modifying or rolling back the database.

The configured minimum command interval applies per grant. Counter and revocation tables each admit at most 4,096 grant IDs; reaching capacity denies new admissions/revocations rather than silently discarding state. Existing revocations are never automatically expired. This protects bounded local behavior but needs an explicit session/key recovery and retention design before continuous fleet operation.

## Data boundary

| Data class | Permitted route | Intentionally absent from analytics output |
| --- | --- | --- |
| Raw camera-like synthetic payload | Sensor to authorized raw-data process | Frame bytes, image text, audio and arbitrary metadata |
| Detailed location and internal state | Trusted processing role and explicitly privileged test observer | Precise pose, unrestricted identifiers and free text |
| Derived robot status | Typed schema: robot ID, enumerated status, battery percentage, coarse grid-cell coordinates and grid size | Any field not in the output schema |
| Authorization decision | Structured stdout response, bounded local decision journal and lab counts | Private keys and raw sensor payloads; an accepted command's bounded fields are deliberately returned to the driver adapter |

Data minimization happens before publication to the lower-trust analytics role. A subscriber filter or a hidden field in a UI is not an authorization boundary. Derived fields can still be sensitive; a deployment must assess their purpose, retention and audience. The repository's fixtures contain no real camera recording, location trail or person.

The local decision journal retains the latest 2,048 entries: monotonic database ID, wall-clock time, allowed/denied flag, bounded reason and SHA-256 input fingerprint. It stores no original input payload. An oversized input passed to the library is fingerprinted only through its bounded prefix; that digest is not proof of the complete rejected message. This journal is not externally anchored, is not encrypted by the application and is not a guarantee of historical completeness. Access controls and retention remain deployment responsibilities.

## Deployment conditions

- Run ROS 2 with security explicitly enabled and enforced; use narrow signed DDS permissions with default denial.
- Give each application process only its own enclave. Keep the identity/permissions CA private keys off the runtime device; the test harness generates temporary keys for its isolated lab.
- Isolate the gateway, driver and raw-data processing role from ordinary clients at the OS/container boundary. Process separation alone is insufficient when every process can read every key.
- Protect issuer and holder private keys, database files and runtime directories. Never upload a generated keystore or secrets as CI artifacts.
- Bind the command path to the intended driver and inspect alternate routes, services and actions. A permissive alternative actuator topic defeats the design.
- Treat deployment configuration as part of the security boundary. A green library unit test cannot validate an unrelated ROS deployment.

These choices follow the role separation and key distribution concerns in the [official ROS 2 deployment guidance](https://raw.githubusercontent.com/ros2/ros2_documentation/jazzy/source/Tutorials/Advanced/Security/Deployment-Guidelines.rst) and [access-control tutorial](https://raw.githubusercontent.com/ros2/ros2_documentation/jazzy/source/Tutorials/Advanced/Security/Access-Controls.rst). Source files are linked because the documentation site may restrict automated access.

## Acceptance map

This maps claims to executable checks, not to a presumed pass. Measured outcomes belong to the run report and CI execution for the commit being reviewed.

| Acceptance | Executable evidence | Controls exercised |
| --- | --- | --- |
| Authority and holder proof | [`tests/security.rs`](../tests/security.rs): `tampered_grant_request_and_forged_holder_are_denied`; [`scripts/check_local_workflow.py`](../scripts/check_local_workflow.py) | Valid proof accepted; modified grant/request and invalid proof rejected; CLI signs with fresh keys |
| Audience and capability | [`tests/security.rs`](../tests/security.rs): `valid_signed_grants_cannot_override_fixed_robot_session_or_principal` | Signed wrong robot, principal, session or operation cannot override configured policy |
| Freshness and numeric limits | [`tests/security.rs`](../tests/security.rs): `expiry_not_before_ttl_stale_future_and_zero_sequence_fail_closed`, `motion_limit_intersects_policy_and_grant_ceiling`, `strict_schema_rejects_unknown_duplicate_fields_nonfinite_and_trailing_json` | Expiration, future/stale time, sequence range, finite limits and parsing boundaries |
| Durable replay protection | [`tests/security.rs`](../tests/security.rs): `replay_and_revocation_persist_across_restarts`, `concurrent_guard_connections_admit_duplicate_only_once` | Reopen preserves revocation/counters; duplicate concurrent requests produce one admission |
| CLI framing and key files | [`tests/cli.rs`](../tests/cli.rs): `oversized_frame_is_audited_and_terminates_before_valid_suffix`, `keygen_never_overwrites_existing_key_and_uses_private_permissions` | Oversized input terminates before a valid suffix can be admitted; key files cannot be silently overwritten |
| Adapter IPC failure | [`tests/test_bridge_ipc.py`](../tests/test_bridge_ipc.py) | Positive two-request control; malformed JSON, duplicate lines in one pipe write and timeout poison the real adapter, terminate the synthetic peer and prohibit reuse. POSIX-only fault injection, not a ROS or Rust authorization test |
| Storage and policy failure | [`tests/security.rs`](../tests/security.rs): `unavailable_audit_rolls_back_sequence_and_never_returns_command`, `locked_state_never_emits_an_authorized_command`, `state_binds_authority_and_policy_and_rejects_invalid_policy` | Injected journal failure rolls back admission; locked state cannot authorize; changed policy/key cannot reuse state |
| Privacy and bounded state | [`tests/security.rs`](../tests/security.rs): `telemetry_projection_excludes_raw_personal_and_exact_position_fields`, `audit_is_bounded_ordered_and_contains_no_raw_payloads`, `state_and_revocation_capacity_fail_closed` | Exact output projection, payload-free bounded journal, capacity denial |
| Real DDS command permissions | [`ros2/run_lab.py`](../ros2/run_lab.py): baseline `authorized_command_caused_synthetic_motion`, `forbidden_publish_denied_at_native_dds_endpoint`, `outsider_command_never_executed` | Authorized control changes synthetic position; outsider cannot create the forbidden command publisher or cause its marked command |
| Real DDS data permissions | [`ros2/run_lab.py`](../ros2/run_lab.py): `authorized_guard_received_signed_raw_sensor_data`, `forbidden_read_denied_at_native_dds_endpoint`, `analytics_received_only_allowlisted_minimal_telemetry` | Protected raw feed demonstrably arrives at the guard; analytics can read only the exact minimized schema |
| Loss of command feed | [`ros2/run_lab.py`](../ros2/run_lab.py): `driver_stopped_after_command_lease_expiry`, `replayed_envelope_never_extends_command_lease` | Synthetic driver returns to zero after lease expiry; replay cannot renew its command |
| Missing or disabled security | [`ros2/run_lab.py`](../ros2/run_lab.py): `enforce_refused_missing_enclave_credentials`, `unsecured_listener_received_no_secured_raw_data` | Missing enclave refuses startup; unsecured reader gets no protected raw messages while authorized reader does |

Local Rust tests and Linux ROS integration are distinct evidence sets. ROS middleware behavior must be measured in the ROS environment. A planned CI job, a generated permissions XML file, or a successful Python import is not an integration pass.

The native graph harness also requires every authorized process to complete without errors. It does not count a crashed planner or missing raw-data producer as a successful block. The `observer` state stream is evidence of the synthetic driver's response, not a physical hardware sensor measurement.

## Next gates before physical deployment

Hardware-specific command semantics and independent stopping; trusted host hardening; key provisioning/rotation; middleware matrix; overload and latency measurements; deliberate network loss; sensor/AI integrity beyond signatures; recovery from state loss; and an external review of the complete robot deployment. No performance advantage, safety integrity level, fleet-scale readiness or regulatory compliance is asserted by this milestone.

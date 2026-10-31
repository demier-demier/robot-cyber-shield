# Threat model

Robot Cyber Shield evaluates an authorization boundary in front of a robot command interface and an information boundary around robot telemetry. Its first test environment is a synthetic ROS 2 robot; it is not a certification of a physical robot, a safety controller, or a guarantee against compromise.

## Assets and trust boundaries

| Asset | Required property | Boundary and owner |
| --- | --- | --- |
| Commands delivered to the synthetic actuator | Only an allowed principal holding a valid mission grant can request an allowed, timely command | Rust guard and ROS 2 gateway; the actuator topic must not be writable by ordinary clients |
| Mission authority signing key | Only the operator can issue permissions | Operator-side key storage; keep the authority private key away from the gateway and robot |
| Command holder signing key | A copied grant alone cannot authorize a command | Client-side key storage; possession of this key is software authorization, not proof of a person's identity |
| Replay and revocation state | Restart must not revive a consumed request or revoked grant | Local durable database; trustworthy storage and host administration are prerequisites |
| Raw sensor payload | Readers outside the sensor processing role cannot receive it | Restrictive DDS topic permissions and separate processes; raw data must not enter analytics output or logs |
| Derived status | Only explicitly permitted fields cross into the analytics role | Typed data minimization; a valid signature does not make a sensor measurement or AI prediction true |
| Decision evidence | Explain decisions without duplicating raw sensor payloads | Bounded SQLite decision journal and lab counts; not an independent or immutable ledger |
| Robot availability and safe motion | Unauthorized activity must not create a command; loss of control must be handled independently | A software command lease can limit continued motion in the synthetic driver. Real equipment needs a hazard analysis and independent stop mechanisms |

ROS 2 security identities belong to DDS participants. Nodes in one process/context can share permissions and memory. A namespace or node name is not an isolation boundary; deploy roles with different data access in separate processes and protect their credentials. See the [ROS 2 enclave design](https://design.ros2.org/articles/ros2_security_enclaves.html).

## Adversaries in scope

Tests use original synthetic messages and actors owned by this repository. They exercise an untrusted command producer, an authenticated but insufficiently privileged ROS participant, a recipient of a copied grant, a replaying client, and an observer trying to receive protected sensor data. They do not scan or exploit another organization's robot, network, account, or infrastructure.

An adversary may know the protocol and public keys, submit malformed input, change message fields, replay captured requests, or try a forbidden DDS topic. In-scope denial is refusal to deliver a command or disclose protected data. Preventing every denial-of-service attack is not claimed.

## Threats and controls

| Threat | Intended control | Residual risk |
| --- | --- | --- |
| Forged or edited mission grant | Verify the authority's Ed25519 signature over a versioned, domain-separated representation | A stolen authority key can issue valid grants; key custody and rotation are operational responsibilities |
| Stolen grant used by a different client | Verify command proof using the holder key bound into the signed grant | Theft of the holder private key defeats this proof until expiration or revocation |
| Correctly signed command sent to the wrong robot or mission | Bind audience, configured principal, session and capability in policy checks | Configuration and identity provisioning must be correct; this does not attest physical robot identity |
| Repeated command after restart | Commit sequence/replay state transactionally before reporting acceptance | Disk rollback, restoring an old database, privileged database editing and disk loss are not prevented by SQLite |
| Lost response followed by retry | Refuse the already-consumed sequence | Acceptance is not proof of actuator execution; a consumed request can be lost between admission and transport |
| Stale, future-dated, expired or revoked request | Check freshness, validity interval and persistent revocation | The host clock is trusted; clock synchronization and rollback protection are not hardware-attested |
| Overspeed, non-finite or malformed command | Strict schema and configured finite limits; reject rather than clip unauthorized requests | Velocity limits do not prove collision avoidance, stability, force safety or a safe path |
| Client bypasses the guard using the actuator topic | Only the gateway enclave may publish actuator commands | A compromised gateway with its credentials can bypass its own application checks |
| Unprivileged participant reads raw sensor data | Default-deny DDS permissions, with explicit raw-reader and analytics roles | A compromised authorized raw-reader can copy data; middleware encryption does not protect data in process memory |
| Excess data leaks into analytics or logs | Explicit output allowlist, structured decision metadata, no raw request echo | Allowed derived data can still reveal operational patterns; this is minimization, not anonymization or differential privacy |
| Missing credentials silently disable security | Explicit `ROS_SECURITY_ENABLE=true`, `ROS_SECURITY_STRATEGY=Enforce`, signed governance and narrow permissions | A host administrator can change the deployment; environment variables are not a hardware trust root |
| State storage fails | Reject authorization when durable state cannot be read or committed | The intended failure mode sacrifices availability; an independent robot-side stop must handle a dead gateway |
| Denial flood displaces audit history | Keep the decision journal bounded at 2,048 entries to constrain local growth | Retention is intentionally finite; a flood can evict old evidence. This is not a forensic preservation system |
| Prompt injection or misleading perception | AI output has no privileged path around authorization and limits | The guard does not decide whether an otherwise authorized task or perception result is correct |

The [ROS 2 DDS security design](https://design.ros2.org/articles/ros2_dds_security) describes authentication, access control and transport cryptography. Security is not enabled by default. A successful authorization test does not independently establish confidentiality of every wire packet, every middleware implementation, or every discovery setting.

The lab also has a privileged `observer` enclave that receives exact synthetic pose from `/robot/state` to verify command effects. That diagnostic channel is deliberately outside the analytics minimization boundary and must not be granted to an ordinary analytics client.

Rate limiting is per grant, not a global per-principal or per-robot rate limiter. Multiple valid grants can each use their own interval. Replay and revocation tables are capped at 4,096 entries each; no automatic fleet lifecycle or expired-grant garbage collection is claimed. Clock rollback checks compare against prior admission for the same grant; they do not establish globally trusted time.

## Out of scope and deployment blockers

- Compromised operating system, root access, debugger access, memory scraping, local credential theft, malicious drivers or firmware, DMA, boot-chain compromise and supply-chain substitution.
- Physical sensor spoofing, adversarial scenes, model poisoning, dangerous but authorized tasks and false measurements signed by a legitimate device.
- Direct access to a motor bus or actuator API that bypasses the protected route. Every alternate command path must be identified and restricted before integration with a robot.
- Certified functional safety, emergency-stop circuitry, force limiting, collision avoidance, safe braking and safety-rated watchdogs. No physical-hardware outcome is inferred from a software driver.
- Guaranteed availability under flooding, real-time scheduling bounds, network partitions or storage exhaustion. Admission and transport latency must be characterized on the target system.
- Database rollback resistance, hardware attestation, secure elements, fleet-scale certificate rotation and independent audit notarization.
- Full protection of a robot's historical datasets, training pipelines, model artifacts or cloud services. This milestone covers command admission and selected live telemetry routes.

The [ROS 2 system threat model](https://design.ros2.org/articles/ros2_threat_model.html) addresses a wider set of robot assets and entry points. [NIST SP 800-82 Rev. 3](https://csrc.nist.gov/pubs/sp/800/82/r3/final) is guidance for OT security in the presence of reliability and safety requirements; citing it is not a claim of certification or compliance.

## Evidence rule

A test passes only when its authorized control works and its unauthorized action has no permitted effect. A timeout, an unavailable middleware implementation, or a node failing before the relevant check is not sufficient evidence of protection. The acceptance map in [ARCHITECTURE.md](ARCHITECTURE.md) names executable checks; measured outcomes belong in the corresponding run report and CI logs.

# Provenance

## Repository material

The application code, tests, lab fixtures and diagrams are original material prepared for this public project. The robot, mission, principals, command streams and sensor samples used in tests are synthetic. No employer or client repository, production robot trace, private recording, personal dataset or proprietary customer configuration is used.

This project implements deterministic authorization and data minimization. A synthetic driver is a software test actor, not a validated physical robot. No AI inference, real-world detection accuracy or physical safety outcome should be inferred from its test results.

## Primary technical references

Reviewed on 2026-10-31. These references informed design; their presence does not constitute an endorsement or certification. Documentation is linked and paraphrased, not bundled as a third-party dataset.

| Reference | How it informs this repository |
| --- | --- |
| [ROS 2 DDS-Security integration](https://design.ros2.org/articles/ros2_dds_security) | Distinguishes participant authentication, topic access control, transport cryptography and explicit enforcement |
| [ROS 2 Security Enclaves](https://design.ros2.org/articles/ros2_security_enclaves.html) | Explains identity scope and why contexts/process composition are part of the trust boundary |
| [ROS 2 robotic systems threat model](https://design.ros2.org/articles/ros2_threat_model.html) | Broader robot assets, physical interfaces, data privacy and residual threats |
| [ROS 2 Jazzy access controls, official source](https://raw.githubusercontent.com/ros2/ros2_documentation/jazzy/source/Tutorials/Advanced/Security/Access-Controls.rst) | Signed per-role permissions, DDS topic names and default denial |
| [ROS 2 Jazzy deployment guidelines, official source](https://raw.githubusercontent.com/ros2/ros2_documentation/jazzy/source/Tutorials/Advanced/Security/Deployment-Guidelines.rst) | Separation of CA private material from device runtime artifacts and minimal enclave distribution |
| [NIST SP 800-82 Rev. 3, final](https://csrc.nist.gov/pubs/sp/800/82/r3/final) | OT security must preserve reliability and consider physical safety; software authorization alone is insufficient |

NIST's publication page also points to a Revision 4 initial public draft at the review date. This repository does not represent that draft as a final standard and does not claim compliance with either revision.

## Dependencies and generated evidence

Rust dependencies are enumerated in `Cargo.toml` and resolved in `Cargo.lock`; their licenses remain their own. ROS 2, SROS2, the RMW implementation, Python and cryptographic utilities are external runtime/test dependencies, not original components. CI and lab reports should record the versions actually used.

Generated certificates, signing keys, SQLite state and raw lab logs are local runtime material. Never commit private keys or upload generated keystores. Public results should contain only reviewed synthetic scenario labels, decision counts, environment versions and measurements actually observed. A passing test with one dependency version is not a promise about every vendor or version.

No benchmark result, customer adoption, production readiness, formal verification or third-party audit is asserted by citing these sources.

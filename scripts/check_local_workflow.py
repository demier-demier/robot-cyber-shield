#!/usr/bin/env python3
"""Exercise the real Rust executable with fresh keys and persistent state.

This checks application authorization, not ROS transport or physical hardware.
All robot identities, commands, and sensor values are original synthetic data.
No private keys, raw telemetry, or machine paths enter the output report.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import tempfile
import time
from pathlib import Path


def run(binary: Path, *args: object) -> None:
    subprocess.run([str(binary), *(str(x) for x in args)], check=True,
                   stdout=subprocess.DEVNULL)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    binary = (args.binary or root / "target" / "debug" /
              ("robot-cyber-shield.exe" if os.name == "nt" else "robot-cyber-shield")).resolve()
    observations = []
    with tempfile.TemporaryDirectory(prefix="robot-shield-check-") as tmp:
        work = Path(tmp)
        for role in ("authority", "holder"):
            run(binary, "keygen", "--private-key", work / f"{role}.private",
                "--public-key", work / f"{role}.public")
        policy = dict(schema="robot-policy/v1", robot_id="lab-rover",
                      session_id="lab-session", command_principal="planner",
                      telemetry_principal="sensor", max_linear_mps=0.5,
                      max_angular_rps=0.5, max_request_age_ms=5000,
                      max_grant_ttl_ms=60000, min_command_interval_ms=0,
                      command_lease_ms=500, position_grid_m=5.0)
        (work / "policy.json").write_text(json.dumps(policy))
        state = work / "state.sqlite"
        sequence = 0

        def now() -> int:
            return time.time_ns() // 1_000_000

        def grant(name: str, capability: str, expired: bool = False) -> Path:
            moment = now()
            claims = dict(schema="robot-grant/v1", grant_id=name,
                          robot_id="lab-rover", session_id="lab-session",
                          principal="planner" if capability == "command" else "sensor",
                          holder_public_key=(work / "holder.public").read_text().strip(),
                          not_before_ms=moment - (10000 if expired else 1000),
                          expires_at_ms=moment - 1 if expired else moment + 30000,
                          capabilities=[capability], max_linear_mps=0.5,
                          max_angular_rps=0.5)
            claims_file = work / f"{name}.claims.json"
            result = work / f"{name}.grant.json"
            claims_file.write_text(json.dumps(claims))
            run(binary, "issue", "--private-key", work / "authority.private",
                "--claims", claims_file, "--output", result)
            return result

        def signed(g: Path, operation: str = "command", **overrides: object) -> dict:
            nonlocal sequence
            sequence += 1
            request = dict(robot_id="lab-rover", session_id="lab-session",
                           principal="planner" if operation == "command" else "sensor",
                           sequence=sequence, issued_at_ms=now())
            if operation == "command":
                request.update(linear_mps=0.2, angular_rps=0.0)
            else:
                request.update(status="idle", battery_percent=78,
                               position_x_m=12.1, position_y_m=-1.1,
                               raw_camera="synthetic-image-do-not-export",
                               raw_audio="synthetic-audio-do-not-export",
                               operator_identity="synthetic-operator-do-not-export")
            request.update(overrides)
            request_file, result = work / f"request-{sequence}.json", work / f"signed-{sequence}.json"
            request_file.write_text(json.dumps(dict(op=operation, request=request)))
            run(binary, "sign-request", "--private-key", work / "holder.private",
                "--grant", g, "--request", request_file, "--output", result)
            return json.loads(result.read_text())

        def evaluate(envelope: dict) -> dict:
            # A new process for every admission exercises persistent counters.
            result = subprocess.run([str(binary), "serve", "--state", str(state),
                                     "--policy", str(work / "policy.json"),
                                     "--public-key", str(work / "authority.public")],
                                    input=json.dumps(envelope) + "\n", text=True,
                                    capture_output=True, check=True)
            return json.loads(result.stdout)

        def check(name: str, envelope: dict, reason: str) -> dict:
            decision = evaluate(envelope)
            assert decision["reason"] == reason, (name, decision)
            assert decision["allowed"] == (reason == "authorized"), (name, decision)
            observations.append(dict(name=name, passed=True, observed_reason=reason))
            return decision

        command_grant = grant("command-001", "command")
        first = signed(command_grant)
        decision = check("signed_command_accepted", first, "authorized")
        assert 0 < decision["command"]["valid_until_ms"] - now() <= 500
        check("same_command_rejected_after_process_restart", first, "replay")
        tampered = signed(command_grant)
        tampered["request"]["linear_mps"] = 0.4
        check("changed_command_signature_rejected", tampered, "invalid_request_signature")
        check("signed_excess_speed_rejected", signed(command_grant, linear_mps=2.0), "motion_limit")
        check("signed_wrong_robot_rejected", signed(command_grant, robot_id="other-rover"), "identity_scope")
        check("expired_signed_grant_rejected", signed(grant("expired-001", "command", True)), "grant_time")
        check("stale_signed_command_rejected", signed(command_grant, issued_at_ms=now()-10000), "request_time_or_sequence")
        telemetry = check("signed_telemetry_minimized", signed(grant("sensor-001", "telemetry"), "telemetry"), "authorized")
        assert set(telemetry["telemetry"]) == {"robot_id", "status", "battery_percent", "position_cell_x", "position_cell_y", "position_grid_m"}
        assert telemetry["telemetry"]["position_cell_x"] == 2
        assert telemetry["telemetry"]["position_cell_y"] == -1
        assert "do-not-export" not in json.dumps(telemetry)
        run(binary, "revoke", "--state", state, "--grant-id", "command-001")
        check("revoked_grant_rejected_after_restart", signed(command_grant), "revoked")
        check("unknown_envelope_fields_rejected", dict(first, override=True), "invalid_schema")
        audit_result = subprocess.run([str(binary), "audit", "--state", str(state),
                                       "--limit", "100"], text=True,
                                      capture_output=True, check=True)
        events = json.loads(audit_result.stdout)
        assert len(events) == len(observations)
        assert len({event["id"] for event in events}) == len(events)
        assert all(set(event) == {"id", "time_ms", "allowed", "reason", "input_sha256"}
                   and len(event["input_sha256"]) == 64 for event in events)
        assert "do-not-export" not in audit_result.stdout
        observations.append(dict(name="persistent_sanitized_decision_audit", passed=True,
                                 observed_events=len(events)))
    report = dict(schema="robot-shield-native-evidence/v1", result="passed",
                  platform=platform.system(), architecture=platform.machine(),
                  scope="Native command authorization and data minimization; no ROS or hardware",
                  scenarios=len(observations), observations=observations)
    encoded = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()

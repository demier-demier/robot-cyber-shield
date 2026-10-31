#!/usr/bin/env python3
"""Exercise real secured DDS processes plus the Rust guard. No mocked ROS API."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

from security_policy import create_keystore


HERE = Path(__file__).resolve().parent
MINIMAL_FIELDS = {"robot_id", "status", "battery_percent", "position_cell_x",
                  "position_cell_y", "position_grid_m"}


def save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def fixture(binary, directory):
    def command(*args):
        subprocess.run([str(binary), *map(str, args)], check=True, timeout=10,
                       stdout=subprocess.DEVNULL)
    for role in ("authority", "planner", "sensor"):
        command("keygen", "--private-key", directory / f"{role}.private",
                "--public-key", directory / f"{role}.public")
    now = time.time_ns() // 1_000_000
    policy = {"schema": "robot-policy/v1", "robot_id": "r1", "session_id": "mission1",
              "command_principal": "planner", "telemetry_principal": "sensor",
              "max_linear_mps": 0.5, "max_angular_rps": 0.8,
              "max_request_age_ms": 2000, "max_grant_ttl_ms": 3600000,
              "min_command_interval_ms": 10, "position_grid_m": 1.0,
              "command_lease_ms": 250}
    save(directory / "policy.json", policy)
    for role, capability in (("planner", "command"), ("sensor", "telemetry")):
        claims = {"schema": "robot-grant/v1", "grant_id": "lab-" + role,
                  "robot_id": "r1", "session_id": "mission1", "principal": role,
                  "holder_public_key": (directory / f"{role}.public").read_text().strip(),
                  "not_before_ms": now - 1000, "expires_at_ms": now + 180000,
                  "capabilities": [capability], "max_linear_mps": 0.5,
                  "max_angular_rps": 0.8}
        save(directory / f"{role}.claims.json", claims)
        command("issue", "--private-key", directory / "authority.private",
                "--claims", directory / f"{role}.claims.json",
                "--output", directory / f"{role}.grant.json")
    config = {"binary": str(binary), "policy": str(directory / "policy.json"),
              "authority_public": str(directory / "authority.public"),
              "state": str(directory / "guard.sqlite")}
    for role in ("planner", "sensor"):
        config[f"{role}_private"] = str(directory / f"{role}.private")
        config[f"{role}_grant"] = str(directory / f"{role}.grant.json")
    config_path = directory / "config.json"
    save(config_path, config)
    return config_path


class Processes:
    def __init__(self, config, environment, work, output):
        self.config, self.environment = config, environment
        self.work, self.output = work, output
        self.items = []

    def start(self, name, mode, role, duration, *extra, insecure=False):
        log = (self.work / f"{name}.log").open("w")
        report = self.output / f"{name}.json"
        environment = dict(self.environment)
        if insecure:
            environment["ROS_SECURITY_ENABLE"] = "false"
        command = [sys.executable, str(HERE / "lab_node.py"), mode,
                   "--config", str(self.config), "--output", str(report),
                   "--duration", str(duration), "--enclave", f"/shield/{role}", *extra]
        process = subprocess.Popen(command, env=environment, stdout=log, stderr=subprocess.STDOUT)
        self.items.append((name, process, log, report))
        return process

    def finish(self, timeout=30):
        deadline = time.monotonic() + timeout
        reports = {}
        for name, process, log, path in self.items:
            try:
                process.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            log.close()
            value = json.loads(path.read_text()) if path.exists() else {"completed": False, "errors": ["NoResult"]}
            value["process_returncode"] = process.returncode
            save(path, value)
            reports[name] = value
            # Only bounded sanitized logs cross the artifact boundary. Never copy
            # keystores, command envelopes, grants, configs, databases or raw frames.
            text = (self.work / f"{name}.log").read_text(errors="replace")[-20000:]
            text = text.replace(str(self.work.parent), "<ephemeral-lab>")
            if "-----BEGIN" in text or "SYNTHETIC_CAMERA_SECRET" in text:
                text = "Log withheld: secret-like content detected; inspect the local run.\n"
            (self.output / f"{name}.log").write_text(text)
        return reports

    def cleanup(self):
        for _, process, log, _ in self.items:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            if not log.closed:
                log.close()


def require(condition, name, checks, detail):
    checks.append({"name": name, "passed": bool(condition), "detail": detail})


def run_case(name, binary, workspace, output, env, attack="none", dds=False):
    work = workspace / name
    destination = output / name
    work.mkdir(mode=0o700)
    destination.mkdir()
    config = fixture(binary, work)
    processes = Processes(config, env, work, destination)
    try:
        # All observers outlive the planner; the last phase must show a zero
        # velocity after the command lease expires while the driver stays alive.
        processes.start("driver", "driver", "driver", 13)
        processes.start("guard", "guard", "guard", 12)
        processes.start("observer", "observer", "observer", 12)
        processes.start("analytics", "observer", "analytics", 12,
                        "--topic", "/robot/telemetry/minimal")
        if dds:
            processes.start("forbidden_publish", "probe", "outsider", 7,
                            "--topic", "/robot/cmd_vel", "--direction", "publish")
            processes.start("forbidden_read", "probe", "analytics", 7,
                            "--topic", "/robot/sensors/raw", "--direction", "subscribe")
            processes.start("missing_credentials", "probe", "missing_identity", 5,
                            "--topic", "/robot/state", "--direction", "subscribe")
            processes.start("insecure_read", "probe", "outsider", 9,
                            "--topic", "/robot/sensors/raw", "--direction", "subscribe",
                            insecure=True)
        time.sleep(1)
        processes.start("planner", "planner", "planner", 7, "--attack", attack)
        reports = processes.finish(timeout=30)
    finally:
        processes.cleanup()
    checks = []
    healthy = ("driver", "guard", "observer", "analytics", "planner")
    require(all(reports[k].get("completed") and reports[k].get("process_returncode") == 0
                and not reports[k].get("errors") for k in healthy),
            "all_authorized_processes_completed", checks,
            {k: {"completed": reports[k].get("completed"), "errors": reports[k].get("errors")}
             for k in healthy})
    guard = reports["guard"]
    driver = reports["driver"]
    analytics = reports["analytics"].get("minimal", [])
    state = reports["observer"].get("state", [])
    require(guard.get("raw_received", 0) >= 5 and guard.get("raw_marker_seen") is True,
            "authorized_guard_received_signed_raw_sensor_data", checks,
            {"raw_messages": guard.get("raw_received", 0), "fixture_marker_seen": guard.get("raw_marker_seen")})
    require(len(analytics) >= 5 and all(set(x) == MINIMAL_FIELDS for x in analytics)
            and not any("SECRET" in json.dumps(x) for x in analytics),
            "analytics_received_only_allowlisted_minimal_telemetry", checks,
            {"messages": len(analytics), "field_allowlist": sorted(MINIMAL_FIELDS)})
    require(len(state) >= 20, "observer_witnessed_live_driver_state", checks, {"samples": len(state)})
    if attack in ("none", "replay"):
        require(driver.get("accepted_commands", 0) > 0 and driver.get("max_x_m", 0) > 0,
                "authorized_command_caused_synthetic_motion", checks,
                {"accepted_commands": driver.get("accepted_commands", 0), "max_x_m": driver.get("max_x_m", 0)})
        require(driver.get("watchdog_stops", 0) >= 1 and state
                and all(x.get("linear_mps") == 0 and x.get("angular_rps") == 0 for x in state[-5:]),
                "driver_stopped_after_command_lease_expiry", checks,
                {"watchdog_stops": driver.get("watchdog_stops", 0)})
        if attack == "none":
            published = reports["planner"].get("messages", 0)
            require(published > 0 and published == guard.get("allowed_commands")
                    and published == driver.get("accepted_commands")
                    and reports["planner"].get("matched_subscriptions_at_first_publish", 0) > 0,
                    "every_command_published_after_discovery_reached_actuator_in_this_run", checks,
                    {"published": published, "allowed": guard.get("allowed_commands"),
                     "executed": driver.get("accepted_commands"),
                     "guard_denial_reasons": guard.get("decision_reasons", {}),
                     "driver_rejection_reasons": driver.get("rejection_reasons", {}),
                     "rejected_receipts": [receipt for receipt in driver.get("command_receipts", [])
                                           if receipt.get("reason") != "accepted"],
                     "discovery_wait_cycles": reports["planner"].get("discovery_wait_cycles"),
                     "first_publish_elapsed_ms": reports["planner"].get("first_publish_elapsed_ms")})
    else:
        require(guard.get("allowed_commands") == 0 and guard.get("denied_commands", 0) >= 5
                and driver.get("accepted_commands") == 0 and driver.get("max_x_m") == 0,
                f"{attack}_requests_did_not_reach_actuator", checks,
                {"allowed": guard.get("allowed_commands"), "denied": guard.get("denied_commands"),
                 "accepted_by_driver": driver.get("accepted_commands"), "x_m": driver.get("max_x_m")})
        reason = {"wrong_holder": "invalid_request_signature", "stale": "request_time_or_sequence",
                  "overspeed": "motion_limit", "tamper": "invalid_request_signature"}[attack]
        require(guard.get("decision_reasons", {}).get(reason, 0) == guard.get("denied_commands")
                and guard.get("denied_commands", 0) >= 5,
                f"{attack}_denied_for_expected_reason", checks,
                {"expected_reason": reason, "observed_reasons": guard.get("decision_reasons", {})})
    if attack == "replay":
        require(guard.get("allowed_commands") == 1 and guard.get("denied_commands", 0) >= 5
                and driver.get("accepted_commands") == 1,
                "replayed_envelope_never_extends_command_lease", checks,
                {"allowed": guard.get("allowed_commands"), "denied": guard.get("denied_commands"),
                 "accepted_by_driver": driver.get("accepted_commands")})
        reasons = guard.get("decision_reasons", {})
        require(reasons.get("replay", 0) > 0
                and set(reasons) <= {"authorized", "replay", "request_time_or_sequence"},
                "replay_denied_by_replay_or_age_after_first_authorization", checks,
                {"observed_reasons": reasons})
    if dds:
        for item in ("forbidden_publish", "forbidden_read"):
            denied = reports[item]
            require(denied.get("initialized") is True and denied.get("endpoint_created") is False
                    and denied.get("failure_stage") == "endpoint" and denied.get("process_returncode") == 2,
                    item + "_denied_at_native_dds_endpoint", checks,
                    {k: denied.get(k) for k in ("initialized", "endpoint_created", "failure_stage", "errors")})
        missing = reports["missing_credentials"]
        require(missing.get("initialized") is False and missing.get("failure_stage") == "init"
                and missing.get("process_returncode") == 2,
                "enforce_refused_missing_enclave_credentials", checks,
                {k: missing.get(k) for k in ("initialized", "failure_stage", "errors")})
        insecure = reports["insecure_read"]
        require(insecure.get("completed") is True and insecure.get("endpoint_created") is True
                and insecure.get("messages") == 0 and guard.get("raw_received", 0) >= 5,
                "unsecured_listener_received_no_secured_raw_data", checks,
                {"unsecured_messages": insecure.get("messages"), "authorized_raw_messages": guard.get("raw_received")})
        require(driver.get("final_state", {}).get("last_sequence", 999999) != 999999,
                "outsider_command_never_executed", checks,
                {"last_sequence": driver.get("final_state", {}).get("last_sequence")})
    summary = {"name": name, "attack": attack, "checks": checks,
               "passed": all(check["passed"] for check in checks)}
    save(destination / "summary.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--domain", type=int, default=73)
    parser.add_argument("--cases", nargs="+", choices=["baseline", "replay", "wrong_holder", "stale", "overspeed", "tamper"],
                        default=["baseline", "replay", "wrong_holder", "stale", "overspeed", "tamper"])
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit("Evidence directory must be empty; refusing to replace a previous run")
    output.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    results = []
    summary = {"schema": "robot-shield-ros2-observed/v1", "passed": False,
               "ros_distribution": os.environ.get("ROS_DISTRO"), "rmw": "rmw_fastrtps_cpp",
               "system": platform.system(), "machine": platform.machine(),
               "actuator": "synthetic_kinematic_stub", "hardware_motion_tested": False,
               "packet_capture_performed": False, "cases": results}
    try:
        with tempfile.TemporaryDirectory(prefix="robot-shield-lab-") as directory:
            workspace = Path(directory)
            keystore = workspace / "keystore"
            create_keystore(keystore, args.domain, output / "security-policy.json")
            env = dict(os.environ, ROS_DOMAIN_ID=str(args.domain), ROS_LOCALHOST_ONLY="1",
                       ROS_SECURITY_KEYSTORE=str(keystore), ROS_SECURITY_ENABLE="true",
                       ROS_SECURITY_STRATEGY="Enforce", RMW_IMPLEMENTATION="rmw_fastrtps_cpp",
                       PYTHONUNBUFFERED="1", RCUTILS_COLORIZED_OUTPUT="0")
            for name in args.cases:
                print(f"Running native ROS2 case: {name}", flush=True)
                results.append(run_case(name, binary, workspace, output, env,
                                        attack="none" if name == "baseline" else name,
                                        dds=name == "baseline"))
                print(f"{name}: {'PASS' if results[-1]['passed'] else 'FAIL'}", flush=True)
            summary["passed"] = all(case["passed"] for case in results)
    except Exception as error:
        summary["setup_error"] = type(error).__name__
        raise
    finally:
        save(output / "summary.json", summary)
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Project reviewed native ROS observations into a public browser evidence file.

The input is the ros2-native-observations artifact from a successful lab run.
Only counts, validation facts and synthetic driver poses cross this boundary.
No keystore, grant, raw sensor payload, log text or absolute timestamp is copied.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re


CASES = ("baseline", "replay", "tamper", "wrong_holder", "stale", "overspeed")
MINIMAL_FIELDS = {"robot_id", "status", "battery_percent", "position_cell_x",
                  "position_cell_y", "position_grid_m"}
MAX_SOURCE_FILE = 300_000
MAX_OUTPUT = 150_000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def build(source: Path, commit: str, ci_url: str) -> dict:
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "Full source commit required")
    require(re.fullmatch(r"https://github.com/demier-demier/robot-cyber-shield/actions/runs/[0-9]+", ci_url)
            is not None, "Expected project CI run URL")
    hashes = {}

    def read(relative, text=False):
        path = source / relative
        require(path.is_file() and not path.is_symlink(), "Source artifact must be a regular file")
        require(path.stat().st_size <= MAX_SOURCE_FILE, "Source artifact exceeds budget")
        raw = path.read_bytes()
        hashes[relative] = hashlib.sha256(raw).hexdigest()
        return raw.decode() if text else json.loads(raw)

    summary = read("summary.json")
    require(summary.get("schema") == "robot-shield-ros2-observed/v1" and summary.get("passed") is True,
            "A successful native ROS lab report is required")
    require(summary.get("hardware_motion_tested") is False
            and summary.get("actuator") == "synthetic_kinematic_stub", "Unexpected actuator provenance")
    cases_by_name = {case["name"]: case for case in summary["cases"]}
    require(set(cases_by_name) == set(CASES) and len(summary["cases"]) == len(CASES),
            "All six distinct controlled scenarios are required")
    observations = {}
    for name in CASES:
        case = cases_by_name[name]
        checks = case["checks"]
        require(case.get("passed") is True and checks and all(c.get("passed") is True for c in checks),
                "Failed checks cannot be displayed as a successful scenario")
        planner = read(f"{name}/planner.json")
        driver = read(f"{name}/driver.json")
        guard = read(f"{name}/guard.json")
        observer = read(f"{name}/observer.json")
        analytics = read(f"{name}/analytics.json")
        for role in (planner, driver, guard, observer, analytics):
            require(role.get("completed") is True and role.get("process_returncode") == 0
                    and role.get("errors") == [], "Authorized control process failed")
        states = observer["state"]
        require(20 <= len(states) <= 1000, "Insufficient or excessive motion observations")
        first_stamp = states[0]["stamp_ms"]
        timeline = []
        previous = -1
        for state in states:
            require(state.get("actuator") == "synthetic_kinematic_stub", "Unexpected physical-source claim")
            relative_time = state["stamp_ms"] - first_stamp
            require(isinstance(relative_time, int) and previous < relative_time <= 90_000,
                    "Driver timeline must be monotonic and bounded")
            previous = relative_time
            row = {"tMs": relative_time, "xM": state["x_m"], "yM": state["y_m"],
                   "yawRad": state["yaw_rad"], "linearMps": state["linear_mps"],
                   "angularRps": state["angular_rps"]}
            require(all(type(v) in (float, int) and math.isfinite(v) and abs(v) <= 1000
                        for k, v in row.items() if k != "tMs"), "Invalid synthetic motion sample")
            timeline.append(row)
        samples = analytics["minimal"]
        require(len(samples) >= 5 and all(set(sample) == MINIMAL_FIELDS for sample in samples),
                "Minimal telemetry contains unexpected fields")
        item = {
            "label": name, "evidenceReplay": True, "durationMs": timeline[-1]["tMs"],
            "commandsPublished": planner["messages"], "commandsAllowed": guard["allowed_commands"],
            "commandsDenied": guard["denied_commands"], "commandsExecuted": driver["accepted_commands"],
            "maxDisplacementM": driver["max_x_m"], "watchdogStops": driver["watchdog_stops"],
            "decisionReasons": guard["decision_reasons"], "rawReceived": guard["raw_received"],
            "minimalPublished": guard["allowed_telemetry"], "minimalReceived": len(samples),
            "minimalFields": sorted(MINIMAL_FIELDS), "timeline": timeline,
            "sourceTimelineSamples": len(states), "checksPassed": len(checks),
            "checkNames": [check["name"] for check in checks],
        }
        require(item["commandsAllowed"] == item["commandsExecuted"], "Admission/execution mismatch")
        if name == "baseline":
            require(item["commandsPublished"] == item["commandsExecuted"] > 0,
                    "Baseline needs observed delivery after discovery")
        elif name == "replay":
            require(item["commandsExecuted"] == 1 and item["commandsDenied"] > 0,
                    "Replay must execute once and reject subsequent attempts")
        else:
            require(item["commandsExecuted"] == 0 and item["maxDisplacementM"] == 0
                    and all(point["xM"] == 0 and point["yM"] == 0 for point in timeline),
                    "Signed negative case must have no actuator effect")
        observations[name] = item

    baseline = observations["baseline"]
    forbidden_read = read("baseline/forbidden_read.json")
    forbidden_publish = read("baseline/forbidden_publish.json")
    for report in (forbidden_read, forbidden_publish):
        require(report.get("initialized") is True and report.get("endpoint_created") is False
                and report.get("failure_stage") == "endpoint" and report.get("process_returncode") == 2,
                "A failed native endpoint with an initialized secured role is required")
    require("rt/robot/sensors/raw topic not found in allow rule" in read("baseline/forbidden_read.log", True),
            "Native DDS raw-reader permission failure must be observed")
    require("rt/robot/cmd_vel topic not found in allow rule" in read("baseline/forbidden_publish.log", True),
            "Native DDS actuator-writer permission failure must be observed")
    missing = read("baseline/missing_credentials.json")
    require(missing.get("initialized") is False and missing.get("failure_stage") == "init",
            "Missing enclave must refuse initialization")
    insecure = read("baseline/insecure_read.json")
    require(insecure.get("completed") is True and insecure.get("endpoint_created") is True
            and insecure.get("messages") == 0 and baseline["rawReceived"] > 0,
            "Unsecured read denial needs a functioning positive raw-data control")
    data = {
        "schema": "robot-shield-visual-evidence/v1", "evidenceReplay": True,
        "source": {"commit": commit, "ciUrl": ci_url, "platform": summary["system"],
                   "architecture": summary["machine"], "rosDistribution": summary["ros_distribution"],
                   "rmw": summary["rmw"], "hardwareMotionTested": False,
                   "packetCapturePerformed": summary["packet_capture_performed"],
                   "actuator": summary["actuator"], "fileSha256": hashes},
        "checks": {"passed": sum(len(case["checks"]) for case in cases_by_name.values()),
                   "total": sum(len(case["checks"]) for case in cases_by_name.values())},
        "timelineSemantics": "Original synthetic driver samples; timestamps are relative to the first observed sample in each independent case. No interpolated sample is presented as measured.",
        "cases": observations,
        "access": {
            "camera": {"case": "baseline", "evidenceReplay": True, "topic": "/robot/sensors/raw",
                       "allowed": False, "nativeEndpointCreated": False, "participantInitialized": True,
                       "securityRequired": True, "rawMessagesReceived": forbidden_read["messages"],
                       "authorizedRawReaderMessages": baseline["rawReceived"],
                       "minimalReaderMessages": baseline["minimalReceived"],
                       "proof": "DDS permissions rejected creation of the raw-data reader.",
                       "cameraPayload": "Synthetic marker in native test; no actual camera footage."},
            "actuatorPublisher": {"case": "baseline", "evidenceReplay": True,
                                  "topic": "/robot/cmd_vel", "allowed": False,
                                  "nativeEndpointCreated": False, "participantInitialized": True,
                                  "commandsPublished": forbidden_publish["messages"],
                                  "proof": "DDS permissions rejected creation of the actuator writer."},
            "missingCredentials": {"case": "baseline", "evidenceReplay": True,
                                   "initialized": False, "failureStage": "init", "securityRequired": True},
            "insecureListener": {"case": "baseline", "evidenceReplay": True,
                                 "endpointCreated": True, "rawMessagesReceived": insecure["messages"],
                                 "authorizedRawReaderMessages": baseline["rawReceived"]},
        },
        "uiCaseMap": {"normal": "baseline", "camera": "baseline", "replay": "replay", "tamper": "tamper",
                      "speed": "overspeed", "wrong_holder": "wrong_holder", "stale": "stale", "telemetry": "baseline"},
    }
    encoded = json.dumps(data, separators=(",", ":"), allow_nan=False)
    require(len(encoded.encode()) < MAX_OUTPUT, "Public evidence exceeds browser budget")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--ci-url", required=True)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "web/data/ros-evidence.json")
    args = parser.parse_args()
    data = build(args.source, args.source_commit, args.ci_url)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, separators=(",", ":"), allow_nan=False) + "\n")
    print(f"Wrote reviewed projection: {len(data['cases'])} cases, {data['checks']['passed']} checks, {args.output.stat().st_size} bytes")


if __name__ == "__main__":
    main()

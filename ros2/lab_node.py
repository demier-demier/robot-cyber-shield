#!/usr/bin/env python3
"""Native ROS2 endpoints for an isolated, synthetic robot security lab."""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time


def now_ms():
    return time.time_ns() // 1_000_000


def write_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(".partial")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")
    temporary.replace(path)


class CoreClient:
    def __init__(self, config):
        self.poisoned = False
        self.process = subprocess.Popen([
            config["binary"], "serve", "--state", config["state"],
            "--policy", config["policy"], "--public-key", config["authority_public"],
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr,
            bufsize=0)

    def decide(self, request):
        if self.poisoned or self.process.poll() is not None:
            raise RuntimeError("Rust guard process exited")
        wire = json.dumps(request, separators=(",", ":"), allow_nan=False)
        if len(wire.encode()) > 64 * 1024:
            raise ValueError("Oversized envelope")
        try:
            self.process.stdin.write((wire + "\n").encode())
            self.process.stdin.flush()
            deadline = time.monotonic() + 2.0
            line = b""
            while not line.endswith(b"\n"):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                    raise TimeoutError("Rust guard response timeout")
                chunk = os.read(self.process.stdout.fileno(), 4096)
                if not chunk:
                    raise ValueError("Rust guard closed response stream")
                line += chunk
                if len(line) > 65536 or b"\n" in line[:-1]:
                    raise ValueError("Invalid Rust guard response framing")
            result = json.loads(line)
            if not isinstance(result, dict) or not isinstance(result.get("allowed"), bool):
                raise ValueError("Invalid Rust guard decision")
            return result
        except Exception:
            # A late response could otherwise be mistaken for the next request's
            # decision. Any IPC failure permanently poisons this process instance.
            self.poisoned = True
            self.process.kill()
            self.process.wait(timeout=2)
            raise

    def close(self):
        if self.process.stdin:
            try:
                self.process.stdin.close()
            except BrokenPipeError:
                pass
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2)


def sign(config, role, operation, request):
    # The Rust CLI performs canonical typed serialization for both signing and
    # verification. Temporary signed envelopes never become CI artifacts.
    with tempfile.TemporaryDirectory(prefix="shield-sign-") as temporary:
        temporary = Path(temporary)
        input_path, output_path = temporary / "request.json", temporary / "envelope.json"
        input_path.write_text(json.dumps({"op": operation, "request": request}))
        subprocess.run([
            config["binary"], "sign-request", "--private-key", config[f"{role}_private"],
            "--grant", config[f"{role}_grant"], "--request", str(input_path),
            "--output", str(output_path),
        ], check=True, timeout=3, stdout=subprocess.DEVNULL)
        return json.loads(output_path.read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["driver", "guard", "planner", "observer", "probe"])
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration", type=float, default=10)
    parser.add_argument("--enclave", required=True)
    parser.add_argument("--topic")
    parser.add_argument("--direction", choices=["publish", "subscribe"])
    parser.add_argument("--attack", choices=["none", "replay", "tamper", "wrong_holder", "stale", "overspeed"], default="none")
    args = parser.parse_args()
    if not 0 < args.duration <= 90:
        raise ValueError("Duration must be bounded to 90 seconds")
    config = json.loads(args.config.read_text())
    report = {"mode": args.mode, "enclave": args.enclave, "initialized": False,
              "endpoint_created": False, "messages": 0, "errors": [], "samples": []}
    node = None
    core = None
    stage = "import"
    try:
        import rclpy
        from rclpy.node import Node
        from rclpy.parameter import Parameter
        from std_msgs.msg import String
        stage = "init"
        rclpy.init(args=["--ros-args", "--enclave", args.enclave])
        node = Node("shield_" + args.mode, enable_rosout=False,
                    start_parameter_services=False,
                    parameter_overrides=[Parameter("start_type_description_service", value=False)])
        report["initialized"] = True
        stage = "endpoint"
        started = time.monotonic()

        def publish(publisher, value):
            publisher.publish(String(data=json.dumps(value, separators=(",", ":"), allow_nan=False)))

        def parse(message):
            if len(message.data.encode()) > 65536:
                raise ValueError("Oversized ROS envelope")
            value = json.loads(message.data)
            if not isinstance(value, dict):
                raise ValueError("Object required")
            return value

        if args.mode == "probe":
            if not args.topic or not args.direction:
                raise ValueError("Probe topic and direction required")
            report["topic"] = args.topic
            if args.direction == "subscribe":
                def received(message):
                    report["messages"] += 1
                node.create_subscription(String, args.topic, received, 10)
            else:
                publisher = node.create_publisher(String, args.topic, 10)
                def attempt():
                    publish(publisher, {"robot_id": "r1", "session_id": "mission1",
                                        "grant_id": "untrusted-outsider",
                                        "sequence": 999999, "linear_mps": 0.4,
                                        "angular_rps": 0.0, "valid_until_ms": now_ms() + 200})
                    report["messages"] += 1
                node.create_timer(0.1, attempt)

        elif args.mode == "observer":
            report["state"] = []
            report["minimal"] = []
            topics = [args.topic] if args.topic else ["/robot/state", "/robot/telemetry/minimal"]
            for topic in topics:
                def record(message, topic=topic):
                    value = parse(message)
                    report["messages"] += 1
                    key = "state" if topic == "/robot/state" else "minimal"
                    if len(report[key]) < 1000:
                        report[key].append(value)
                node.create_subscription(String, topic, record, 50)

        elif args.mode == "guard":
            core = CoreClient(config)
            report.update({"allowed_commands": 0, "denied_commands": 0,
                           "allowed_telemetry": 0, "denied_telemetry": 0,
                           "decision_reasons": {}, "raw_received": 0,
                           "raw_marker_seen": False})
            command_pub = node.create_publisher(String, "/robot/cmd_vel", 10)
            minimal_pub = node.create_publisher(String, "/robot/telemetry/minimal", 10)

            def ingress(message, operation):
                try:
                    envelope = parse(message)
                    if operation == "telemetry":
                        report["raw_received"] += 1
                        report["raw_marker_seen"] |= "SYNTHETIC_CAMERA_SECRET" in message.data
                    decision = core.decide(envelope)
                    reason = str(decision.get("reason", "unspecified"))
                    report["decision_reasons"][reason] = report["decision_reasons"].get(reason, 0) + 1
                    field = "command" if operation == "command" else "telemetry"
                    # A response must match the ingress operation; no cross-topic forwarding.
                    if decision["allowed"] and isinstance(decision.get(field), dict):
                        publish(command_pub if operation == "command" else minimal_pub, decision[field])
                        report["allowed_commands" if operation == "command" else "allowed_telemetry"] += 1
                    else:
                        report["denied_commands" if operation == "command" else "denied_telemetry"] += 1
                except Exception as error:
                    # Do not forward on any parsing, IPC or Rust failure.
                    report["errors"].append(type(error).__name__)

            node.create_subscription(String, "/shield/requests", lambda msg: ingress(msg, "command"), 20)
            node.create_subscription(String, "/robot/sensors/raw", lambda msg: ingress(msg, "telemetry"), 20)

        elif args.mode == "planner":
            publisher = node.create_publisher(String, "/shield/requests", 10)
            sequence = 0
            replay_envelope = None
            report["discovery_wait_cycles"] = 0
            report["first_publish_elapsed_ms"] = None
            report["matched_subscriptions_at_first_publish"] = 0

            def plan():
                nonlocal sequence, replay_envelope
                # Give DDS discovery time before publishing signed fixtures.
                if time.monotonic() - started < 2.0:
                    return
                matched = publisher.get_subscription_count()
                if matched == 0:
                    report["discovery_wait_cycles"] += 1
                    return
                if report["first_publish_elapsed_ms"] is None:
                    report["first_publish_elapsed_ms"] = round((time.monotonic() - started) * 1000)
                    report["matched_subscriptions_at_first_publish"] = matched
                sequence += 1
                request = {"robot_id": "r1", "session_id": "mission1", "principal": "planner",
                           "sequence": sequence, "issued_at_ms": now_ms() - (10000 if args.attack == "stale" else 0),
                           "linear_mps": 0.25 if args.attack != "overspeed" else 2.0,
                           "angular_rps": 0.0}
                if args.attack == "replay" and replay_envelope is not None:
                    envelope = replay_envelope
                else:
                    envelope = sign(config, "planner", "command", request)
                    if args.attack == "wrong_holder":
                        other = sign(config, "sensor", "command", request)
                        envelope["request_signature"] = other["request_signature"]
                    if args.attack == "tamper":
                        # Same authorized holder and grant, changed command after signing.
                        envelope["request"]["linear_mps"] = 0.4
                    replay_envelope = envelope
                publish(publisher, envelope)
                report["messages"] += 1
            node.create_timer(0.15, plan)

        elif args.mode == "driver":
            state = {"x_m": 0.0, "y_m": 0.0, "yaw_rad": 0.0,
                     "linear_mps": 0.0, "angular_rps": 0.0,
                     "last_sequence": -1, "valid_until_ms": 0}
            report.update({"accepted_commands": 0, "rejected_commands": 0,
                           "watchdog_stops": 0, "max_x_m": 0.0, "telemetry_sent": 0})
            state_pub = node.create_publisher(String, "/robot/state", 20)
            raw_pub = node.create_publisher(String, "/robot/sensors/raw", 10)
            previous_tick = time.monotonic()
            sensor_sequence = 0
            accepted_sequences = {}

            def command(message):
                try:
                    value = parse(message)
                    valid = (value["robot_id"] == "r1" and value["session_id"] == "mission1"
                             and isinstance(value["grant_id"], str)
                             and 0 < len(value["grant_id"]) <= 128
                             and isinstance(value["sequence"], int)
                             and value["sequence"] > accepted_sequences.get(value["grant_id"], -1)
                             and (value["grant_id"] in accepted_sequences or len(accepted_sequences) < 128)
                             and now_ms() < value["valid_until_ms"] <= now_ms() + 1000
                             and math.isfinite(value["linear_mps"])
                             and math.isfinite(value["angular_rps"])
                             and abs(value["linear_mps"]) <= 0.5
                             and abs(value["angular_rps"]) <= 0.8)
                    if not valid:
                        raise ValueError("Rejected command or lease")
                    for key in ("linear_mps", "angular_rps", "valid_until_ms"):
                        state[key] = value[key]
                    state["last_sequence"] = value["sequence"]
                    accepted_sequences[value["grant_id"]] = value["sequence"]
                    report["accepted_commands"] += 1
                except (ValueError, TypeError, KeyError):
                    report["rejected_commands"] += 1

            def tick():
                nonlocal previous_tick
                current = time.monotonic()
                dt = min(0.2, current - previous_tick)
                previous_tick = current
                if now_ms() >= state["valid_until_ms"]:
                    if state["linear_mps"] or state["angular_rps"]:
                        report["watchdog_stops"] += 1
                    state["linear_mps"] = state["angular_rps"] = 0.0
                state["yaw_rad"] += state["angular_rps"] * dt
                state["x_m"] += state["linear_mps"] * math.cos(state["yaw_rad"]) * dt
                state["y_m"] += state["linear_mps"] * math.sin(state["yaw_rad"]) * dt
                report["max_x_m"] = max(report["max_x_m"], state["x_m"])
                publish(state_pub, dict(state, stamp_ms=now_ms(), actuator="synthetic_kinematic_stub"))

            def sensor():
                nonlocal sensor_sequence
                sensor_sequence += 1
                request = {"robot_id": "r1", "session_id": "mission1", "principal": "sensor",
                           "sequence": sensor_sequence, "issued_at_ms": now_ms(),
                           "status": "moving" if state["linear_mps"] else "idle",
                           "battery_percent": 80, "position_x_m": state["x_m"],
                           "position_y_m": state["y_m"],
                           "raw_camera": "SYNTHETIC_CAMERA_SECRET",
                           "raw_audio": "SYNTHETIC_AUDIO_SECRET",
                           "operator_identity": "SYNTHETIC_OPERATOR_SECRET"}
                publish(raw_pub, sign(config, "sensor", "telemetry", request))
                report["telemetry_sent"] += 1
            node.create_subscription(String, "/robot/cmd_vel", command, 20)
            node.create_timer(0.1, tick)
            node.create_timer(0.4, sensor)
            report["final_state"] = state

        report["endpoint_created"] = True
        stage = "spin"
        while time.monotonic() - started < args.duration:
            rclpy.spin_once(node, timeout_sec=0.05)
        report["completed"] = True
    except Exception as error:
        report["failure_stage"] = stage
        report["errors"].append(type(error).__name__)
        # Keep runtime DDS errors for diagnosis, never signed envelopes or key data.
        print(f"{stage}: {type(error).__name__}: {error}", file=sys.stderr)
        report["completed"] = False
    finally:
        if core:
            core.close()
        if node:
            node.destroy_node()
        try:
            import rclpy
            if rclpy.ok():
                rclpy.shutdown()
        except Exception:
            pass
        write_json(args.output, report)
    return 0 if report.get("completed") else 2


if __name__ == "__main__":
    raise SystemExit(main())

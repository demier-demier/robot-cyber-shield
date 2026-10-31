"""Exercise synthetic-driver rejection diagnostics; no ROS or hardware claim."""

import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "shield_driver_diagnostics", Path(__file__).resolve().parents[1] / "ros2/lab_node.py")
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)


class DriverAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.command = dict(robot_id="r1", session_id="mission1", grant_id="synthetic-grant",
                            sequence=1, valid_until_ms=1250, linear_mps=0.25, angular_rps=0.0)

    def test_valid_control_and_expiry_boundary(self):
        original = dict(self.command)
        self.assertIsNone(LAB.driver_rejection_reason(self.command, {}, 1000))
        self.assertIsNone(LAB.driver_rejection_reason(self.command, {}, 1249))
        self.assertEqual(LAB.driver_rejection_reason(self.command, {}, 1250), "lease_expired")
        self.assertEqual(LAB.driver_rejection_reason(self.command, {}, 1300), "lease_expired")
        self.assertEqual(self.command, original, "diagnostics must never renew or edit the lease")

    def test_reason_codes_distinguish_constraints(self):
        for changes, reason in [
            ({"robot_id": "wrong"}, "identity_scope"),
            ({"grant_id": ""}, "grant_identity"),
            ({"sequence": "1"}, "sequence_type"),
            ({"valid_until_ms": 2001}, "lease_too_long"),
            ({"valid_until_ms": float("nan")}, "lease_expired"),
            ({"linear_mps": float("inf")}, "nonfinite_motion"),
            ({"angular_rps": 0.81}, "motion_limit"),
            ({"valid_until_ms": "private-payload"}, "malformed_command"),
        ]:
            with self.subTest(reason=reason):
                self.assertEqual(LAB.driver_rejection_reason(dict(self.command, **changes), {}, 1000), reason)
        self.assertEqual(LAB.driver_rejection_reason({}, {}, 1000), "malformed_command")

    def test_replay_and_capacity_remain_denied(self):
        self.assertEqual(LAB.driver_rejection_reason(self.command, {"synthetic-grant": 1}, 1000), "sequence_replay")
        occupied = {f"synthetic-{i}": 1 for i in range(128)}
        self.assertEqual(LAB.driver_rejection_reason(self.command, occupied, 1000), "grant_capacity")
        self.assertEqual(len(occupied), 128)

    def test_diagnostics_do_not_echo_payloads(self):
        sample = LAB.bounded_command_sample(dict(self.command, camera="DO_NOT_EXPORT"), reason="lease_expired")
        self.assertEqual(sample, {"sequence": 1, "reason": "lease_expired"})
        for sequence in ("DO_NOT_EXPORT", True, 2**64):
            self.assertIsNone(LAB.bounded_command_sample({"sequence": sequence})["sequence"])


if __name__ == "__main__":
    unittest.main()

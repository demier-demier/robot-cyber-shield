"""Verify the public evidence projection against committed native observations.

These tests check evidence integrity and privacy, not a new ROS execution.
The native middleware run remains linked by its original commit and CI URL.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("demo_evidence_builder", ROOT / "scripts/build_demo_evidence.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)
COMMIT = "76024ea1044288f67a45c400c26e64b8e11152be"
CI = "https://github.com/demier-demier/robot-cyber-shield/actions/runs/41248935977"


class DemoEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = ROOT / "web/data/ros-evidence.json"
        cls.wire = cls.path.read_text()
        cls.data = json.loads(cls.wire)
        cls.observed_path = ROOT / "docs/results/ros2-2026-10-31.json"
        cls.observed = json.loads(cls.observed_path.read_text())

    def test_evidence_is_bound_to_successful_native_report(self):
        self.assertTrue(self.data["evidenceReplay"])
        self.assertFalse(self.data["source"]["hardwareMotionTested"])
        self.assertFalse(self.data["source"]["packetCapturePerformed"])
        self.assertEqual(self.data["source"]["commit"], COMMIT)
        self.assertEqual(self.data["source"]["ciUrl"], CI)
        self.assertEqual(self.data["source"]["fileSha256"]["summary.json"],
                         hashlib.sha256(self.observed_path.read_bytes()).hexdigest())
        checks = [check for case in self.observed["cases"] for check in case["checks"]]
        self.assertEqual(self.data["checks"], {"passed": 44, "total": len(checks)})
        self.assertTrue(all(check["passed"] for check in checks))

    def test_command_counts_match_measured_native_cases(self):
        expected = {
            "baseline": (19, 19, 0, 19), "replay": (33, 1, 32, 1),
            "tamper": (32, 0, 32, 0), "wrong_holder": (31, 0, 31, 0),
            "stale": (33, 0, 33, 0), "overspeed": (33, 0, 33, 0),
        }
        for name, counts in expected.items():
            with self.subTest(name=name):
                case = self.data["cases"][name]
                self.assertEqual(tuple(case[key] for key in ("commandsPublished", "commandsAllowed",
                                                            "commandsDenied", "commandsExecuted")), counts)
                self.assertTrue(case["evidenceReplay"])
                original = next(c for c in self.observed["cases"] if c["name"] == name)
                self.assertEqual(case["checkNames"], [c["name"] for c in original["checks"]])
                self.assertEqual(case["checksPassed"], len(original["checks"]))

    def test_timelines_keep_samples_relative_monotonic_and_motion_bound(self):
        fields = {"tMs", "xM", "yM", "yawRad", "linearMps", "angularRps"}
        for name, case in self.data["cases"].items():
            with self.subTest(name=name):
                timeline = case["timeline"]
                self.assertEqual(len(timeline), case["sourceTimelineSamples"])
                self.assertGreaterEqual(len(timeline), 100)
                self.assertEqual(timeline[0]["tMs"], 0)
                self.assertEqual(case["durationMs"], timeline[-1]["tMs"])
                self.assertLessEqual(case["durationMs"], 90_000)
                self.assertTrue(all(a["tMs"] < b["tMs"] for a, b in zip(timeline, timeline[1:])))
                self.assertTrue(all(set(point) == fields and all(math.isfinite(v) for v in point.values())
                                    for point in timeline))
                self.assertTrue(all(point["linearMps"] == 0 for point in timeline[-5:]))
                self.assertAlmostEqual(max(point["xM"] for point in timeline), case["maxDisplacementM"], places=8)
                if name not in ("baseline", "replay"):
                    self.assertEqual(case["maxDisplacementM"], 0)
                    self.assertTrue(all(point["linearMps"] == 0 and point["xM"] == 0 for point in timeline))

    def test_camera_denial_has_native_positive_controls(self):
        camera = self.data["access"]["camera"]
        self.assertTrue(camera["evidenceReplay"])
        self.assertTrue(camera["participantInitialized"])
        self.assertFalse(camera["nativeEndpointCreated"])
        self.assertFalse(camera["allowed"])
        self.assertEqual(camera["rawMessagesReceived"], 0)
        self.assertEqual(camera["authorizedRawReaderMessages"], 29)
        self.assertEqual(camera["minimalReaderMessages"], 29)
        self.assertEqual(camera["topic"], "/robot/sensors/raw")
        self.assertEqual(self.data["access"]["insecureListener"]["rawMessagesReceived"], 0)
        self.assertEqual(self.data["uiCaseMap"]["camera"], "baseline")

    def test_output_contains_only_allowlisted_data_and_no_raw_payload(self):
        self.assertLess(self.path.stat().st_size, BUILDER.MAX_OUTPUT)
        forbidden_keys = {"stamp_ms", "valid_until_ms", "raw_camera", "raw_audio", "operator_identity",
                          "request_signature", "holder_public_key", "private_key", "grant", "config"}

        def visit(value):
            if isinstance(value, dict):
                self.assertFalse(set(value) & forbidden_keys)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)
        visit(self.data)
        for marker in ("/Users/", "BEGIN PRIVATE", "SYNTHETIC_CAMERA_SECRET", "SYNTHETIC_OPERATOR_SECRET",
                       "SYNTHETIC_AUDIO_SECRET", "github_pat_", "ghp_"):
            self.assertNotIn(marker, self.wire)
        for case in self.data["cases"].values():
            self.assertEqual(set(case["minimalFields"]), BUILDER.MINIMAL_FIELDS)

    def test_tamper_case_preserves_exact_rejection_reason(self):
        for name, reason in (("tamper", "invalid_request_signature"), ("wrong_holder", "invalid_request_signature"),
                             ("stale", "request_time_or_sequence"), ("overspeed", "motion_limit")):
            case = self.data["cases"][name]
            self.assertEqual(case["decisionReasons"][reason], case["commandsDenied"])
        replay = self.data["cases"]["replay"]
        self.assertEqual(replay["decisionReasons"]["replay"], 13)
        self.assertEqual(replay["decisionReasons"]["request_time_or_sequence"], 19)

    def test_builder_rejects_invalid_provenance_and_failed_native_run(self):
        with tempfile.TemporaryDirectory(prefix="shield-evidence-check-") as folder:
            path = Path(folder)
            with self.assertRaisesRegex(ValueError, "Full source commit"):
                BUILDER.build(path, "not-a-commit", CI)
            with self.assertRaisesRegex(ValueError, "Expected project CI"):
                BUILDER.build(path, COMMIT, "https://example.com/not-evidence")
            (path / "summary.json").write_text(json.dumps({"schema": "robot-shield-ros2-observed/v1", "passed": False}))
            with self.assertRaisesRegex(ValueError, "successful native ROS"):
                BUILDER.build(path, COMMIT, CI)


if __name__ == "__main__":
    unittest.main()

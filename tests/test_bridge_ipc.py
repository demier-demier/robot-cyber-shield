"""Fault-inject the real CoreClient subprocess boundary, without loading ROS.

The subprocesses below are explicit synthetic IPC peers, not implementations of
Rust authorization or mocks of DDS security. These tests establish framing and
failure handling only; native ROS execution is covered by ros2/run_lab.py.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("shield_lab_ipc", ROOT / "ros2/lab_node.py")
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)


@unittest.skipUnless(os.name == "posix", "CoreClient uses POSIX pipe/select semantics")
class BridgeIpcTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="shield-ipc-test-")
        self.clients = []

    def tearDown(self):
        for client in self.clients:
            client.close()
            if client.process.stdout:
                client.process.stdout.close()
        self.temporary.cleanup()

    def client(self, body):
        peer = Path(self.temporary.name) / f"peer-{len(self.clients)}"
        peer.write_text(
            f"#!{sys.executable}\n"
            "import os, sys, time\n"
            + body
            + "\n"
        )
        peer.chmod(0o700)
        # Paths are intentionally unused by the synthetic peer. It exercises
        # CoreClient's actual launch, write, select, framing and cleanup code.
        client = LAB.CoreClient({
            "binary": str(peer),
            "state": "unused-synthetic-state",
            "policy": "unused-synthetic-policy",
            "authority_public": "unused-synthetic-key",
        })
        self.clients.append(client)
        return client

    def assert_poisoned_after(self, body, error_type):
        client = self.client(body)
        with self.assertRaises(error_type):
            client.decide({"synthetic_request": 1})
        self.assertTrue(client.poisoned)
        self.assertIsNotNone(client.process.poll(), "failed peer must be terminated")
        # A late/partial reply must never become the next request's decision.
        with self.assertRaises(RuntimeError):
            client.decide({"synthetic_request": 2})

    def test_well_framed_responses_keep_client_usable(self):
        client = self.client(
            "for request in sys.stdin.buffer:\n"
            "    os.write(1, b'{\"allowed\":false,\"reason\":\"synthetic_control\"}\\n')"
        )
        for sequence in (1, 2):
            self.assertEqual(
                client.decide({"synthetic_request": sequence}),
                {"allowed": False, "reason": "synthetic_control"},
            )
            self.assertFalse(client.poisoned)
            self.assertIsNone(client.process.poll())

    def test_malformed_json_poisons_client_and_prevents_reuse(self):
        self.assert_poisoned_after(
            "sys.stdin.buffer.readline()\n"
            "os.write(1, b'not-json\\n')\n"
            "time.sleep(10)",
            ValueError,
        )

    def test_duplicate_response_lines_poison_client_and_prevent_reuse(self):
        self.assert_poisoned_after(
            "sys.stdin.buffer.readline()\n"
            # One atomic pipe write makes both lines part of the same response.
            "os.write(1, b'{\"allowed\":false}\\n{\"allowed\":true}\\n')\n"
            "time.sleep(10)",
            ValueError,
        )

    def test_delayed_response_poisons_client_and_prevents_reuse(self):
        self.assert_poisoned_after(
            "sys.stdin.buffer.readline()\n"
            # Longer than CoreClient's deadline; it must kill this peer before
            # the delayed acceptance can be emitted or reused.
            "time.sleep(10)\n"
            "os.write(1, b'{\"allowed\":true}\\n')",
            TimeoutError,
        )


if __name__ == "__main__":
    unittest.main()

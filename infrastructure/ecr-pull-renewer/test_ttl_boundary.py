"""Focused v2 boundary: all mutation/readback margins match the 7200s contract."""
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import refresh_once as runtime
from test_pure_refresh import NOW, UID
from test_refresh_once import FakeKube, FakeECR


class TTLBoundaryTests(unittest.TestCase):
    def test_5400_seconds_is_rejected_before_patch_and_after_ack_without_relabel(self):
        with mock.patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            before = FakeKube()
            # FakeECR returns an authorization that expires NOW+43200. The
            # fresh pre-PATCH clock leaves 5400 seconds, below the 7200 contract.
            clock = mock.Mock(side_effect=[NOW, NOW + 43200 - 5400])
            with self.assertRaisesRegex(runtime.Hold, "^expiry_margin_lost_before_patch$"):
                runtime.run_cycle(before, FakeECR(), UID, clock=clock)
            self.assertEqual(before.patch_calls, 0)
            after = FakeKube()
            clock = mock.Mock(side_effect=[NOW, NOW, NOW + 43200 - 5400])
            with self.assertRaises(runtime.CycleFailure) as raised:
                runtime.run_cycle(after, FakeECR(), UID, clock=clock)
            value = raised.exception.public_result
            self.assertEqual(after.patch_calls, 1)
            self.assertEqual(value["status"], "PATCH_RESULT_UNCONFIRMED")
            self.assertEqual(value["patch_transport"], "acknowledged")
            self.assertEqual(value["patch_http_status"], 200)
            self.assertNotIn("REFRESH_CONFIRMED", json.dumps(value))
            # The stated contract is >=7200, matching build_plan's boundary.
            exact = FakeKube()
            clock = mock.Mock(side_effect=[NOW, NOW + 43200 - 7200, NOW + 43200 - 7200])
            self.assertEqual(runtime.run_cycle(exact, FakeECR(), UID, clock=clock)["status"], "REFRESH_CONFIRMED")
            self.assertEqual(exact.patch_calls, 1)


if __name__ == "__main__":
    unittest.main()

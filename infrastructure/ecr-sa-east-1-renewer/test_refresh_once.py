"""Offline runtime tests; no main(), SDK requests, or service access."""

import builtins
import copy
import datetime
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import refresh_once as runtime
from pure_refresh import ValidationError
from test_pure_refresh import NOW, UID, authorization, secret


class SimulatedCrash(BaseException):
    pass


class FakeKube:
    """Model an API that can commit before its caller loses the reply."""

    def __init__(self, patch_outcome="acknowledged", before=None):
        self.current = copy.deepcopy(before if before is not None else secret())
        self.patch_outcome = patch_outcome
        self.get_calls = 0
        self.patch_calls = 0
        self.patches = []
        self.get_error_at = None

    def get_secret(self):
        self.get_calls += 1
        if self.get_calls == self.get_error_at:
            raise runtime.TransportFailure()
        return copy.deepcopy(self.current)

    def patch_secret(self, patch):
        self.patch_calls += 1
        self.patches.append(copy.deepcopy(patch))
        if self.patch_outcome == "crash":
            raise SimulatedCrash()
        if self.patch_outcome == "http403":
            raise runtime.TransportFailure(403)
        if self.patch_outcome == "timeout_without_commit":
            raise runtime.TransportFailure()
        if self.patch_outcome == "concurrent_change":
            self.current["metadata"]["resourceVersion"] = "opaque-concurrent-version"
        if (patch[0]["value"] != self.current["metadata"]["uid"]
                or patch[1]["value"] != self.current["metadata"]["resourceVersion"]):
            raise runtime.TransportFailure(409)
        self.current["data"][".dockerconfigjson"] = patch[2]["value"]
        self.current["metadata"]["resourceVersion"] = "opaque-committed-version-" + str(self.patch_calls)
        if self.patch_outcome == "timeout_with_commit":
            raise runtime.TransportFailure()
        if self.patch_outcome == "http503_with_commit":
            raise runtime.TransportFailure(503)


class FakeECR:
    def __init__(self):
        self.calls = 0

    def authorization(self):
        self.calls += 1
        return authorization(password="synthetic-new-generation-" + str(self.calls))


def forbid_sdk_import(name, *args, **kwargs):
    if name == "boto3" or name == "botocore" or name.startswith("botocore."):
        raise AssertionError("SDK import before metadata validation")
    return ORIGINAL_IMPORT(name, *args, **kwargs)


ORIGINAL_IMPORT = builtins.__import__


class RuntimeRefreshTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(runtime, "exchange", side_effect=AssertionError("network forbidden")).start()
        mock.patch("socket.socket.connect", side_effect=AssertionError("network forbidden")).start()
        self.kube = FakeKube()
        self.ecr = FakeECR()

    def cycle(self, kube=None):
        return runtime.run_cycle(kube or self.kube, self.ecr, UID, clock=lambda: NOW)

    def test_acknowledged_patch_is_sent_once_and_other_data_is_preserved(self):
        original = copy.deepcopy(self.kube.current)
        result = self.cycle()
        self.assertEqual(result["status"], "REFRESH_CONFIRMED")
        self.assertEqual(result["patch_transport"], "acknowledged")
        self.assertEqual((self.kube.get_calls, self.kube.patch_calls, self.ecr.calls), (2, 1, 1))
        self.assertEqual(self.kube.current["metadata"]["uid"], UID)
        self.assertEqual(self.kube.current["data"]["other-key"], original["data"]["other-key"])
        token = authorization(password="synthetic-new-generation-1")["authorizationData"][0]["authorizationToken"]
        self.assertNotIn(token, json.dumps(result))

    def test_lost_patch_reply_with_committed_state_keeps_transport_uncertain(self):
        self.kube.patch_outcome = "timeout_with_commit"
        result = self.cycle()
        self.assertEqual(result["status"], "STATE_OBSERVED_AFTER_UNCERTAIN_PATCH")
        self.assertEqual(result["patch_transport"], "uncertain")
        self.assertTrue(result["state_exactly_observed"])
        self.assertEqual(self.kube.patch_calls, 1)
        self.assertEqual((self.kube.get_calls, self.ecr.calls), (2, 1))

    def test_lost_reply_without_commit_is_not_retried_but_next_job_rotates_fresh(self):
        self.kube.patch_outcome = "timeout_without_commit"
        with self.assertRaises(runtime.CycleFailure) as raised:
            self.cycle()
        self.assertEqual(raised.exception.public_result["patch_transport"], "uncertain")
        self.assertIsNone(raised.exception.public_result["patch_http_status"])
        self.assertEqual(self.kube.patch_calls, 1)
        self.assertEqual((self.kube.get_calls, self.ecr.calls), (2, 1))
        self.kube.patch_outcome = "acknowledged"
        result = self.cycle()
        self.assertEqual(result["status"], "REFRESH_CONFIRMED")
        self.assertEqual((self.kube.get_calls, self.kube.patch_calls, self.ecr.calls), (4, 2, 2))
        self.assertNotEqual(self.kube.patches[0][2]["value"], self.kube.patches[1][2]["value"])

    def test_crashed_job_has_no_internal_resend_and_distinct_job_reads_fresh(self):
        self.kube.patch_outcome = "crash"
        with self.assertRaises(SimulatedCrash):
            self.cycle()
        self.assertEqual((self.kube.get_calls, self.kube.patch_calls, self.ecr.calls), (1, 1, 1))
        self.kube.patch_outcome = "acknowledged"
        result = self.cycle()
        self.assertEqual(result["status"], "REFRESH_CONFIRMED")
        self.assertEqual((self.kube.get_calls, self.kube.patch_calls, self.ecr.calls), (3, 2, 2))

    def test_http403_stops_job_without_readback_or_resend_and_next_job_is_fresh(self):
        self.kube.patch_outcome = "http403"
        with self.assertRaises(runtime.CycleFailure) as raised:
            self.cycle()
        self.assertEqual(raised.exception.public_result["status"], "PATCH_HTTP_ERROR")
        self.assertEqual(raised.exception.public_result["patch_http_status"], 403)
        self.assertEqual(raised.exception.public_result["patch_transport"], "http_error")
        self.assertEqual((self.kube.get_calls, self.kube.patch_calls), (1, 1))
        self.assertEqual(self.ecr.calls, 1)
        self.kube.patch_outcome = "acknowledged"
        result = self.cycle()
        self.assertEqual(result["status"], "REFRESH_CONFIRMED")
        self.assertEqual((self.kube.get_calls, self.kube.patch_calls, self.ecr.calls), (3, 2, 2))

    def test_recreated_secret_stops_before_requesting_ecr_credentials(self):
        self.kube.current["metadata"]["uid"] = "replacement-secret-uid"
        with self.assertRaisesRegex(ValidationError, "^secret_identity$"):
            self.cycle()
        self.assertEqual((self.kube.get_calls, self.kube.patch_calls, self.ecr.calls), (1, 0, 0))

    def test_unreadable_readback_preserves_failure_and_next_job_uses_new_version(self):
        self.kube.get_error_at = 2
        with self.assertRaises(runtime.CycleFailure) as raised:
            self.cycle()
        self.assertEqual(raised.exception.public_result["status"], "PATCH_RESULT_UNCONFIRMED")
        self.assertEqual(raised.exception.public_result["patch_transport"], "acknowledged")
        self.assertEqual((self.kube.get_calls, self.kube.patch_calls, self.ecr.calls), (2, 1, 1))
        self.kube.get_error_at = None
        result = self.cycle()
        self.assertEqual(result["status"], "REFRESH_CONFIRMED")
        self.assertEqual((self.kube.get_calls, self.kube.patch_calls, self.ecr.calls), (4, 2, 2))
        self.assertEqual(self.kube.patches[1][1]["value"], "opaque-committed-version-1")
        self.assertNotEqual(self.kube.patches[0][2]["value"], self.kube.patches[1][2]["value"])

    def test_concurrent_secret_change_rejects_stale_cas_without_resend(self):
        self.kube.patch_outcome = "concurrent_change"
        with self.assertRaises(runtime.CycleFailure) as raised:
            self.cycle()
        self.assertEqual(raised.exception.public_result["patch_http_status"], 409)
        self.assertEqual((self.kube.get_calls, self.kube.patch_calls, self.ecr.calls), (1, 1, 1))
        self.kube.patch_outcome = "acknowledged"
        result = self.cycle()
        self.assertEqual(result["status"], "REFRESH_CONFIRMED")
        self.assertEqual(self.kube.patches[1][1]["value"], "opaque-concurrent-version")
        self.assertNotEqual(self.kube.patches[0][2]["value"], self.kube.patches[1][2]["value"])

    def test_http503_can_commit_and_readback_retains_uncertain_transport(self):
        self.kube.patch_outcome = "http503_with_commit"
        result = self.cycle()
        self.assertEqual(result["status"], "STATE_OBSERVED_AFTER_UNCERTAIN_PATCH")
        self.assertEqual(result["patch_transport"], "uncertain")
        self.assertEqual(result["patch_http_status"], 503)
        self.assertEqual((self.kube.get_calls, self.kube.patch_calls, self.ecr.calls), (2, 1, 1))

    def test_clock_advancing_during_token_acquisition_prevents_patch(self):
        clock = mock.Mock(side_effect=[NOW, NOW + 43200])
        with self.assertRaisesRegex(runtime.Hold, "^expiry_margin_lost_before_patch$"):
            runtime.run_cycle(self.kube, self.ecr, UID, clock=clock)
        self.assertEqual((self.kube.get_calls, self.kube.patch_calls, self.ecr.calls), (1, 0, 1))

    def test_already_current_token_skips_patch_and_second_get(self):
        plan = runtime.build_plan(secret(), authorization(password="synthetic-new-generation-1"), UID, NOW)
        self.kube.current["data"][".dockerconfigjson"] = plan.expected_encoded
        result = self.cycle()
        self.assertEqual(result["status"], "NO_PATCH_ALREADY_CURRENT")
        self.assertEqual(result["patch_transport"], "not_sent")
        self.assertEqual((self.kube.get_calls, self.kube.patch_calls, self.ecr.calls), (1, 0, 1))

    def host_config(self):
        return {
            "expected_instance_id": "i-0123456789abcdef0",
            "existing_instance_profile_arn": "arn:aws:iam::123456789012:instance-profile/synthetic-profile",
            "existing_role_name": "synthetic-role",
        }

    def metadata_responses(self, config, expiry):
        return [
            b"synthetic-imdsv2-session",
            config["expected_instance_id"].encode(),
            json.dumps({"Code": "Success", "InstanceProfileArn": config["existing_instance_profile_arn"]}).encode(),
            config["existing_role_name"].encode(),
            json.dumps({"Code": "Success", "Expiration": expiry,
                        "AccessKeyId": "synthetic-key", "SecretAccessKey": "synthetic-secret",
                        "Token": "synthetic-session"}).encode(),
        ]

    def test_metadata_token_failure_never_falls_back_to_imdsv1_or_sdk(self):
        with mock.patch.object(runtime, "exchange", side_effect=runtime.TransportFailure(403)) as exchange:
            with mock.patch("builtins.__import__", side_effect=forbid_sdk_import):
                with self.assertRaises(runtime.TransportFailure) as raised:
                    runtime.HostECR(self.host_config()).authorization()
        self.assertEqual(raised.exception.status, 403)
        self.assertEqual(exchange.call_count, 1)
        self.assertEqual(exchange.call_args.args[:2], ("http://169.254.169.254/latest/api/token", "PUT"))

    def test_changed_metadata_identity_stops_before_credentials_endpoint_or_sdk(self):
        config = self.host_config()
        replies = self.metadata_responses(config, "2099-01-01T00:00:00Z")
        replies[1] = b"i-fffffffffffffffff"
        with mock.patch.object(runtime, "exchange", side_effect=replies) as exchange:
            with mock.patch("builtins.__import__", side_effect=forbid_sdk_import):
                with self.assertRaisesRegex(runtime.Hold, "^host_identity_changed$"):
                    runtime.HostECR(config).authorization()
        self.assertEqual(exchange.call_count, 4)
        self.assertTrue(all("X-aws-ec2-metadata-token" in call.kwargs["headers"]
                            for call in exchange.call_args_list[1:]))

    def test_expired_metadata_credentials_stop_before_sdk_or_other_provider(self):
        config = self.host_config()
        expiry = datetime.datetime.fromtimestamp(NOW - 1, datetime.timezone.utc).isoformat()
        replies = self.metadata_responses(config, expiry)
        with mock.patch.object(runtime, "exchange", side_effect=replies) as exchange:
            with mock.patch.object(runtime.time, "time", return_value=NOW):
                with mock.patch("builtins.__import__", side_effect=forbid_sdk_import):
                    with self.assertRaisesRegex(runtime.Hold, "^imds_credentials_invalid$"):
                        runtime.HostECR(config).authorization()
        self.assertEqual(exchange.call_count, 5)


if __name__ == "__main__":
    unittest.main()

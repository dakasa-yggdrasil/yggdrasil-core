"""Offline admission/projection/SDK tests. SDK wheels live only in work/."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import refresh_once as runtime
import render_manifest
from test_pure_refresh import NOW, authorization


def admitted():
    config = json.loads((HERE / "ADMISSION.TEMPLATE.json").read_bytes())
    config.update({key: True for key in runtime.APPROVAL_FLAGS})
    config.update(expected_secret_uid="12345678-1234-4234-8234-123456789abc",
                  public_identity_evidence_ref="synthetic-public-identity-proof",
                  public_kube_evidence_ref="synthetic-public-kube-proof")
    return config


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        mock.patch("socket.socket.connect", side_effect=AssertionError("network forbidden")).start()

    def test_null_template_blocks_before_any_client(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(sys, "argv", ["refresh_once", "--admission", "synthetic"]):
            with mock.patch.object(runtime, "input_path", return_value="synthetic"), mock.patch.object(runtime, "private_read", return_value=(HERE / "ADMISSION.TEMPLATE.json").read_bytes()):
                with mock.patch.object(runtime, "KubeSecret", side_effect=AssertionError("client forbidden")), contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(runtime.main(), 78)
        value = json.loads(output.getvalue())
        self.assertEqual(value, {"status": "HOLD", "error_class": "Hold", "reason": "fresh_principal_admission_required"})

    def test_admission_requires_each_fact_and_exact_projection(self):
        runtime.admit(admitted(), check_files=False)
        for key in runtime.APPROVAL_FLAGS:
            config = admitted(); config[key] = None
            with self.assertRaises(runtime.Hold):
                runtime.admit(config, check_files=False)
        config = admitted(); config["kube_token_file"] = "/etc/rancher/k3s/k3s.yaml"
        with self.assertRaises(runtime.Hold):
            runtime.admit(config, check_files=False)

    def test_uncertain_state_observed_still_returns_78_without_secret_output(self):
        result = {"status": "STATE_OBSERVED_AFTER_UNCERTAIN_PATCH", "patch_transport": "uncertain", "state_exactly_observed": True}
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(sys, "argv", ["refresh_once", "--admission", "synthetic"]):
            with mock.patch.object(runtime, "input_path", return_value="synthetic"), mock.patch.object(runtime, "private_read", return_value=json.dumps(admitted()).encode()), mock.patch.object(runtime, "admit"), mock.patch.object(runtime, "KubeSecret"), mock.patch.object(runtime, "HostECR"), mock.patch.object(runtime, "run_cycle", return_value=result):
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(runtime.main(), 78)
        self.assertEqual(json.loads(output.getvalue()), result)

    def test_projected_symlink_rotation_and_escape(self):
        with tempfile.TemporaryDirectory(dir=HERE.parent.parent / "work") as tmp:
            root = Path(tmp) / "projection"; root.mkdir(mode=0o755)
            for name in ("v1", "v2"):
                directory = root / name; directory.mkdir(mode=0o755)
                token = directory / "token"; token.write_text(name); token.chmod(0o400)
            visible = root / "token"; visible.symlink_to("v1/token")
            mapping = {str(visible): str(root)}
            with mock.patch.object(runtime, "PROJECTED_FILES", mapping), \
                    mock.patch.object(runtime, "PROJECTED_CANONICAL_ROOTS", {str(root): str(root)}), \
                    mock.patch.object(runtime.os, "statvfs", return_value=type("ReadOnlyMount", (), {"f_flag": os.ST_RDONLY})()):
                self.assertEqual(runtime.private_read(runtime.input_path(str(visible))), b"v1")
                visible.unlink(); visible.symlink_to("v2/token")
                self.assertEqual(runtime.private_read(runtime.input_path(str(visible))), b"v2")
                outside = Path(tmp) / "outside"; outside.write_text("outside"); outside.chmod(0o400)
                visible.unlink(); visible.symlink_to(outside)
                with self.assertRaises(runtime.Hold):
                    runtime.input_path(str(visible))

    def test_kube_reopens_token_for_each_operation(self):
        config = admitted()
        with mock.patch.object(runtime, "input_path", side_effect=lambda value: value), mock.patch.object(runtime.ssl, "create_default_context"):
            client = runtime.KubeSecret(config)
            with mock.patch.object(runtime, "private_read", side_effect=[b"synthetic.one", b"synthetic.two"]), mock.patch.object(runtime, "exchange", return_value=b"{}") as exchange:
                client.get_secret(); client.patch_secret([])
        self.assertEqual([c.args[2]["Authorization"] for c in exchange.call_args_list], ["Bearer synthetic.one", "Bearer synthetic.two"])
        self.assertTrue(all(c.args[0].endswith("/api/v1/namespaces/dakasa/secrets/ecr-pull-fresh") for c in exchange.call_args_list))

    def test_manifest_scope_no_host_storage_and_offline_renderer(self):
        template = json.loads((HERE / "KUBERNETES.TEMPLATE.json").read_bytes())
        role = next(x for x in template["items"] if x["kind"] == "Role")
        self.assertEqual(role["rules"], [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["ecr-pull-fresh"], "verbs": ["get", "patch"]}])
        cron = next(x for x in template["items"] if x["kind"] == "CronJob")
        self.assertTrue(cron["spec"]["suspend"])
        self.assertEqual(cron["spec"]["concurrencyPolicy"], "Forbid")
        job = cron["spec"]["jobTemplate"]["spec"]
        self.assertEqual((job["backoffLimit"], job["activeDeadlineSeconds"]), (0, 120))
        pod = job["template"]["spec"]
        self.assertEqual(pod["restartPolicy"], "Never")
        self.assertFalse(any("hostPath" in volume for volume in pod["volumes"]))
        self.assertNotIn("imagePullSecrets", pod)
        self.assertIsNone(pod["containers"][0]["image"])
        with tempfile.TemporaryDirectory(dir=HERE.parent.parent / "work") as tmp:
            config = Path(tmp) / "admission.json"; config.write_text(json.dumps(admitted()))
            output = Path(tmp) / "manifest.json"
            with mock.patch.object(sys, "argv", ["render_manifest", "--admission", str(config), "--image", "ghcr.io/example/renewer@sha256:" + "0" * 64, "--output", str(output)]), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(render_manifest.main(), 0)
            rendered = json.loads(output.read_bytes())
            self.assertTrue(next(x for x in rendered["items"] if x["kind"] == "CronJob")["spec"]["suspend"])

    def test_renderer_blocks_all_private_ecr_endpoint_families(self):
        suffix = "/renewer@sha256:" + "0" * 64
        for host in ("123456789012.dkr.ecr.us-east-1.amazonaws.com",
                     "123456789012.dkr.ecr-fips.us-east-1.amazonaws.com",
                     "123456789012.dkr-ecr.us-east-1.on.aws",
                     "123456789012.dkr-ecr-fips.us-east-1.on.aws"):
            self.assertFalse(render_manifest.public_pinned_image(host + suffix))
        self.assertTrue(render_manifest.public_pinned_image("public.ecr.aws/example" + suffix))
        self.assertFalse(render_manifest.public_pinned_image("ghcr.io/example/renewer:latest"))

    @unittest.skipUnless(os.environ.get("ECR_TEST_SDK_DIR"), "isolated locked SDK wheels required")
    def test_real_locked_sdk_stubber_uses_only_explicit_imds_credentials(self):
        sys.path.insert(0, os.environ["ECR_TEST_SDK_DIR"])
        import boto3
        from botocore.stub import Stubber
        real_session = boto3.Session
        c = admitted()
        replies = [b"synthetic-imds-token", c["expected_instance_id"].encode(),
                   json.dumps({"Code": "Success", "InstanceProfileArn": c["existing_instance_profile_arn"]}).encode(), c["existing_role_name"].encode(),
                   json.dumps({"Code": "Success", "Expiration": "2099-01-01T00:00:00Z", "AccessKeyId": "synthetic-key", "SecretAccessKey": "synthetic-secret", "Token": "synthetic-session"}).encode()]
        calls = []
        def factory(*, botocore_session):
            self.assertEqual(botocore_session.get_config_variable("config_file"), os.devnull)
            self.assertEqual(botocore_session.get_config_variable("credentials_file"), os.devnull)
            session = real_session(botocore_session=botocore_session)
            class Wrapped:
                def client(inner, *args, **kwargs):
                    calls.append(kwargs)
                    actual = session.client(*args, **kwargs)
                    stub = Stubber(actual)
                    stub.add_response("get_authorization_token", authorization(), {})
                    stub.activate()
                    return actual
            return Wrapped()
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(runtime, "exchange", side_effect=replies) as exchange, mock.patch.object(boto3, "Session", side_effect=factory), mock.patch.object(runtime.time, "time", return_value=NOW):
            value = runtime.HostECR(c).authorization()
        self.assertEqual(value, authorization())
        self.assertEqual(exchange.call_count, 5)
        self.assertEqual(calls[0]["aws_access_key_id"], "synthetic-key")
        self.assertEqual(calls[0]["aws_session_token"], "synthetic-session")
        self.assertEqual(calls[0]["config"].retries["total_max_attempts"], 1)
        self.assertEqual(calls[0]["endpoint_url"], "https://api.ecr.us-east-1.amazonaws.com")


if __name__ == "__main__":
    unittest.main()

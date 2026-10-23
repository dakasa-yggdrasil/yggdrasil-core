"""Offline sa-east-1 fork contract; all service replies and credentials synthetic."""
import base64
import builtins
import contextlib
import copy
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pure_refresh as pure
import refresh_once as runtime
import render_manifest as renderer
from test_pure_refresh import NOW, UID, authorization, secret

REGISTRY = "153828470928.dkr.ecr.sa-east-1.amazonaws.com"
OLD_REGISTRY = "153828470928.dkr.ecr.us-east-1.amazonaws.com"
IDENTITY = "ecr-pull-sa-east-1-renewer"


class RegionalClosedTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        mock.patch("socket.socket.connect", side_effect=AssertionError("network forbidden")).start()
        mock.patch.object(runtime, "private_read", side_effect=AssertionError("private file forbidden")).start()

    def test_program_fork_is_only_exact_closed_constant_substitution(self):
        expected = {
            "pure_refresh.py": "407ebbbb7bf3b418095f39eb29efcbea19ca8b996be298e79efc005118819334",
            "refresh_once.py": "b54606e4b51acd28de86cf114ffaa385be5d74dc29fa8364df612b6ea8e2b733",
            "render_manifest.py": "07e0c2392e41bfff244c3c7d6b869f2fa6ad5f8addedae301d51c07beee0a619",
        }
        for name, digest in expected.items():
            text = (HERE / name).read_text()
            restored = text.replace("ecr-pull-sa-east-1", "ecr-pull-fresh") if name == "pure_refresh.py" else text
            restored = restored.replace(REGISTRY, OLD_REGISTRY)
            restored = restored.replace('region_name="sa-east-1", endpoint_url="https://api.ecr.sa-east-1.amazonaws.com"',
                                        'region_name="us-east-1", endpoint_url="https://api.ecr.us-east-1.amazonaws.com"')
            restored = restored.replace("system:serviceaccount:dakasa:" + IDENTITY,
                                        "system:serviceaccount:dakasa:ecr-pull-renewer")
            with self.subTest(file=name):
                self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(), digest)
        self.assertEqual((pure.NAMESPACE, pure.SECRET_NAME, pure.REGISTRY),
                         ("dakasa", "ecr-pull-sa-east-1", REGISTRY))

    def test_dedicated_template_is_exact_v4_fork_with_single_secret_get_patch(self):
        text = (HERE / "KUBERNETES.TEMPLATE.json").read_text()
        restored = text.replace(IDENTITY, "ecr-pull-renewer").replace("ecr-pull-sa-east-1", "ecr-pull-fresh")
        self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(),
                         "a06892068dbed5d30d07206906ce00ce964498e6e99f51934800ae53fc29e122")
        template = pure.strict_json(text.encode())
        objects = {x["kind"]: x for x in template["items"]}
        for kind in ("ServiceAccount", "Role", "RoleBinding", "CronJob"):
            self.assertEqual(objects[kind]["metadata"], {"name": IDENTITY, "namespace": "dakasa"})
        self.assertEqual(objects["Role"]["rules"], [{"apiGroups": [""], "resources": ["secrets"],
            "resourceNames": ["ecr-pull-sa-east-1"], "verbs": ["get", "patch"]}])
        self.assertEqual(objects["RoleBinding"]["roleRef"]["name"], IDENTITY)
        self.assertEqual(objects["RoleBinding"]["subjects"], [{"kind": "ServiceAccount", "name": IDENTITY, "namespace": "dakasa"}])
        cron = objects["CronJob"]
        self.assertIs(cron["spec"]["suspend"], True)
        pod = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]
        self.assertEqual(pod["serviceAccountName"], IDENTITY)
        self.assertEqual(pod["volumes"][0]["configMap"]["name"], IDENTITY + "-admission")
        self.assertIsNone(pod["containers"][0]["image"])
        admission = pure.strict_json((HERE / "ADMISSION.TEMPLATE.json").read_bytes())
        self.assertEqual(pure.strict_json(objects["ConfigMap"]["data"]["admission.json"].encode()), admission)
        for key in ("approved_by_principal", "expected_secret_uid", "kube_single_secret_scope_confirmed",
                    "public_identity_evidence_ref", "public_kube_evidence_ref"):
            self.assertIsNone(admission[key])

    def test_regional_pair_accepts_and_old_secret_registry_or_endpoint_rejects(self):
        pure.validate_before(secret(), UID)
        before = secret(); before["metadata"]["name"] = "ecr-pull-fresh"
        with self.assertRaisesRegex(pure.ValidationError, "^secret_identity$"):
            pure.validate_before(before, UID)
        before = secret({"auths": {OLD_REGISTRY: {"auth": "synthetic-old"}}})
        with self.assertRaisesRegex(pure.ValidationError, "^dockerconfig_entry$"):
            pure.validate_before(before, UID)
        response = authorization(); response["authorizationData"][0]["proxyEndpoint"] = "https://" + OLD_REGISTRY
        with self.assertRaisesRegex(pure.ValidationError, "^authorization_endpoint$"):
            pure.build_plan(secret(), response, UID, NOW)

    def test_regional_patch_preserves_other_region_and_exact_uid_rv_cas(self):
        document = {"auths": {REGISTRY: {"auth": "synthetic-old"}, OLD_REGISTRY: {"auth": "synthetic-core"}}}
        before = secret(document)
        original = copy.deepcopy(before)
        plan = pure.build_plan(before, authorization(), UID, NOW)
        updated = pure.strict_json(base64.b64decode(plan.expected_encoded))
        self.assertEqual(updated["auths"][OLD_REGISTRY], document["auths"][OLD_REGISTRY])
        self.assertEqual(plan.patch[:2], [{"op": "test", "path": "/metadata/uid", "value": UID},
            {"op": "test", "path": "/metadata/resourceVersion", "value": "opaque-original-version"}])
        self.assertEqual([(x["op"], x["path"]) for x in plan.patch[2:]], [("replace", "/data/.dockerconfigjson")])
        self.assertEqual(before, original)

    def host_config(self):
        return {"expected_instance_id": "i-0123456789abcdef0", "existing_role_name": "synthetic-role",
                "existing_instance_profile_arn": "arn:aws:iam::123456789012:instance-profile/synthetic-profile"}

    def replies(self, config):
        return [b"synthetic-imdsv2", config["expected_instance_id"].encode(),
                json.dumps({"Code": "Success", "InstanceProfileArn": config["existing_instance_profile_arn"]}).encode(),
                config["existing_role_name"].encode(),
                json.dumps({"Code": "Success", "Expiration": "2099-01-01T00:00:00Z", "AccessKeyId": "synthetic-key",
                            "SecretAccessKey": "synthetic-secret", "Token": "synthetic-session"}).encode()]

    def test_regional_client_uses_only_validated_imdsv2_explicit_credentials(self):
        config = self.host_config()
        sdk = {name: ModuleType(name) for name in ("boto3", "botocore", "botocore.session", "botocore.config")}
        botocore_session = mock.Mock()
        sdk["botocore"].session = sdk["botocore.session"]
        sdk["botocore.session"].Session = mock.Mock(return_value=botocore_session)
        sdk["botocore.config"].Config = mock.Mock(side_effect=lambda **kwargs: kwargs)
        client = mock.Mock(); client.get_authorization_token.return_value = authorization()
        session = mock.Mock(); session.client.return_value = client
        sdk["boto3"].Session = mock.Mock(return_value=session)
        with mock.patch.dict(sys.modules, sdk), mock.patch.object(runtime, "exchange", side_effect=self.replies(config)) as exchange:
            with mock.patch.object(runtime.time, "time", return_value=NOW):
                self.assertEqual(runtime.HostECR(config).authorization(), authorization())
        self.assertEqual(exchange.call_count, 5)
        self.assertEqual(exchange.call_args_list[0].args, ("http://169.254.169.254/latest/api/token", "PUT",
                          {"X-aws-ec2-metadata-token-ttl-seconds": "60"}))
        self.assertTrue(all(x.kwargs["headers"] == {"X-aws-ec2-metadata-token": "synthetic-imdsv2"}
                            for x in exchange.call_args_list[1:]))
        botocore_session.set_config_variable.assert_has_calls([mock.call("config_file", os.devnull), mock.call("credentials_file", os.devnull)])
        session.client.assert_called_once_with("ecr", region_name="sa-east-1", endpoint_url="https://api.ecr.sa-east-1.amazonaws.com",
            aws_access_key_id="synthetic-key", aws_secret_access_key="synthetic-secret", aws_session_token="synthetic-session", verify=True,
            config={"signature_version": "v4", "connect_timeout": 3, "read_timeout": 6,
                    "retries": {"total_max_attempts": 1, "mode": "standard"}, "proxies": {}, "ignore_configured_endpoint_urls": True})
        client.get_authorization_token.assert_called_once_with()
        client.close.assert_called_once_with()

    def test_imdsv2_failure_identity_or_expiry_never_reaches_sdk(self):
        original_import = builtins.__import__
        def no_sdk(name, *args, **kwargs):
            if name == "boto3" or name == "botocore" or name.startswith("botocore."):
                raise AssertionError("SDK forbidden before IMDSv2 validation")
            return original_import(name, *args, **kwargs)
        for defect in ("token_failure", "invalid_token", "instance", "profile", "role", "short_expiry"):
            config = self.host_config(); replies = self.replies(config)
            if defect == "token_failure": replies = runtime.TransportFailure(403)
            if defect == "invalid_token": replies[0] = b"synthetic\ninvalid"
            if defect == "instance": replies[1] = b"i-fffffffffffffffff"
            if defect == "profile": replies[2] = b'{"Code":"Success","InstanceProfileArn":"synthetic-other"}'
            if defect == "role": replies[3] = b"synthetic-other"
            if defect == "short_expiry":
                credentials = json.loads(replies[4]); credentials["Expiration"] = datetime.datetime.fromtimestamp(NOW + 299, datetime.timezone.utc).isoformat(); replies[4] = json.dumps(credentials).encode()
            with self.subTest(defect=defect), mock.patch("builtins.__import__", side_effect=no_sdk):
                with mock.patch.object(runtime, "exchange", side_effect=replies) as exchange, mock.patch.object(runtime.time, "time", return_value=NOW):
                    with self.assertRaises((runtime.Hold, runtime.TransportFailure)):
                        runtime.HostECR(config).authorization()
                    self.assertEqual(exchange.call_count, 1 if defect in ("token_failure", "invalid_token") else 5 if defect == "short_expiry" else 4)

    def test_renderer_accepts_only_regional_identity_and_never_operates_cluster(self):
        config = pure.strict_json((HERE / "ADMISSION.TEMPLATE.json").read_bytes())
        config.update({key: True for key in runtime.APPROVAL_FLAGS})
        config.update(expected_secret_uid="12345678-1234-4234-8234-123456789abc",
                      public_identity_evidence_ref="synthetic-public-identity", public_kube_evidence_ref="synthetic-public-kube")
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(runtime, "exchange", side_effect=AssertionError("HTTP forbidden")):
            admission = Path(temporary) / "admission.json"; output = Path(temporary) / "manifest.json"
            admission.write_text(json.dumps(config))
            argv = ["render_manifest", "--admission", str(admission), "--image", "ghcr.io/example/renewer@sha256:" + "0" * 64, "--output", str(output)]
            with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(renderer.main(), 0)
            cron = next(x for x in json.loads(output.read_bytes())["items"] if x["kind"] == "CronJob")
            self.assertEqual(cron["metadata"]["name"], IDENTITY)
            self.assertIs(cron["spec"]["suspend"], True)
            config["kube_identity"] = "system:serviceaccount:dakasa:ecr-pull-renewer"
            admission.write_text(json.dumps(config))
            with mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                renderer.main()
            self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()

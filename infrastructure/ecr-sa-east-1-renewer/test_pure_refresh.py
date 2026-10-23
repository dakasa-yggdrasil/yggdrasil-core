"""Offline tests using synthetic Secret and ECR responses only."""

import base64
import copy
import datetime
import json
import unittest

from pure_refresh import (
    NAMESPACE,
    REGISTRY,
    SECRET_NAME,
    ValidationError,
    build_plan,
    strict_json,
    validate_before,
    verify_readback,
)


NOW = 1800000000.0
UID = "synthetic-secret-uid"


def encoded(value):
    return base64.b64encode(json.dumps(value).encode()).decode()


def secret(document=None):
    if document is None:
        document = {
            "auths": {
                REGISTRY: {
                    "auth": "synthetic-old-auth",
                    "username": "AWS",
                    "password": "synthetic-old-password",
                    "email": "synthetic@example.invalid",
                },
                "other.example.invalid": {"auth": "synthetic-other-auth"},
            },
            "custom": {"nested": [1, False, "preserve"]},
        }
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": SECRET_NAME,
            "namespace": NAMESPACE,
            "uid": UID,
            "resourceVersion": "opaque-original-version",
            "annotations": {"synthetic": "preserve"},
        },
        "type": "kubernetes.io/dockerconfigjson",
        "immutable": False,
        "data": {
            ".dockerconfigjson": encoded(document),
            "other-key": base64.b64encode(b"synthetic-other-data").decode(),
        },
    }


def authorization(ttl=43200, password="synthetic-new-password:with-colon"):
    return {
        "authorizationData": [
            {
                "proxyEndpoint": "https://" + REGISTRY,
                "expiresAt": datetime.datetime.fromtimestamp(
                    NOW + ttl, datetime.timezone.utc
                ),
                "authorizationToken": base64.b64encode(
                    ("AWS:" + password).encode()
                ).decode(),
            }
        ]
    }


def readback(plan):
    after = copy.deepcopy(plan.before)
    after["metadata"]["resourceVersion"] = "opaque-next-version"
    after["data"][".dockerconfigjson"] = plan.expected_encoded
    return after


class PureRefreshTests(unittest.TestCase):
    def test_strict_json_accepts_nested_object(self):
        self.assertEqual(strict_json(b'{"a":{"b":[1,true,null]}}'), {"a": {"b": [1, True, None]}})

    def test_strict_json_rejects_duplicates_at_any_depth(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":{"private-key":1,"private-key":2}}'):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValidationError, "^json_duplicate_key$"):
                strict_json(raw)

    def test_strict_json_rejects_nonfinite_and_nonobjects(self):
        for raw in (b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}', b'{"a":1e999}', b'[]', b'null', b'{', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises(ValidationError):
                strict_json(raw)

    def test_before_requires_fresh_expected_uid_and_exact_object(self):
        for field, value in (("kind", "ConfigMap"), ("apiVersion", "v2"), ("type", "Opaque")):
            before = secret()
            before[field] = value
            with self.subTest(field=field), self.assertRaises(ValidationError):
                validate_before(before, UID)
        for key, value in (("uid", "replacement-uid"), ("name", "other-secret"), ("namespace", "default"), ("resourceVersion", 12), ("resourceVersion", "")):
            before = secret()
            before["metadata"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValidationError):
                validate_before(before, UID)
        with self.assertRaisesRegex(ValidationError, "^expected_uid_required$"):
            validate_before(secret(), None)

    def test_before_rejects_deleting_or_immutable_secret(self):
        before = secret()
        before["metadata"]["deletionTimestamp"] = "synthetic-deletion"
        with self.assertRaisesRegex(ValidationError, "^secret_deleting$"):
            validate_before(before, UID)
        for immutable in (True, "false", 0):
            before = secret()
            before["immutable"] = immutable
            with self.subTest(immutable=immutable), self.assertRaisesRegex(ValidationError, "^secret_immutable$"):
                validate_before(before, UID)

    def test_before_rejects_malformed_or_missing_docker_auth(self):
        documents = ({}, {"auths": []}, {"auths": {}}, {"auths": {REGISTRY: {}}}, {"auths": {REGISTRY: {"auth": 1}}})
        for document in documents:
            with self.subTest(document=document), self.assertRaises(ValidationError):
                validate_before(secret(document), UID)
        before = secret()
        before["data"][".dockerconfigjson"] = "invalid-base64!"
        with self.assertRaisesRegex(ValidationError, "^dockerconfig_base64$"):
            validate_before(before, UID)

    def test_before_rejects_duplicate_registry_without_losing_entry(self):
        before = secret()
        raw = ('{"auths":{"' + REGISTRY + '":{"auth":"first"},"' + REGISTRY + '":{"auth":"second"}}}').encode()
        before["data"][".dockerconfigjson"] = base64.b64encode(raw).decode()
        with self.assertRaisesRegex(ValidationError, "^json_duplicate_key$"):
            build_plan(before, authorization(), UID, NOW)

    def test_plan_preserves_other_registries_document_and_secret_data(self):
        before = secret()
        original = copy.deepcopy(before)
        response = authorization()
        plan = build_plan(before, response, UID, NOW)
        old = strict_json(base64.b64decode(before["data"][".dockerconfigjson"]))
        new = strict_json(base64.b64decode(plan.expected_encoded))
        self.assertEqual(new["auths"]["other.example.invalid"], old["auths"]["other.example.invalid"])
        self.assertEqual(new["custom"], old["custom"])
        self.assertEqual(new["auths"][REGISTRY]["email"], old["auths"][REGISTRY]["email"])
        self.assertEqual(new["auths"][REGISTRY]["auth"], response["authorizationData"][0]["authorizationToken"])
        self.assertEqual(new["auths"][REGISTRY]["password"], "synthetic-new-password:with-colon")
        self.assertEqual(before, original)
        verify_readback(plan, readback(plan))

    def test_plan_does_not_add_username_or_password_fields(self):
        before = secret({"auths": {REGISTRY: {"auth": "old", "custom": "preserve"}}})
        plan = build_plan(before, authorization(), UID, NOW)
        entry = strict_json(base64.b64decode(plan.expected_encoded))["auths"][REGISTRY]
        self.assertEqual(set(entry), {"auth", "custom"})

    def test_plan_is_detached_and_repr_does_not_expose_credentials(self):
        before = secret()
        plan = build_plan(before, authorization(), UID, NOW)
        before["data"].clear()
        self.assertIn(".dockerconfigjson", plan.before["data"])
        self.assertNotIn("synthetic", repr(plan))
        self.assertNotIn(plan.expected_encoded, repr(plan))

    def test_patch_is_only_uid_version_tests_and_docker_replace(self):
        plan = build_plan(secret(), authorization(), UID, NOW)
        self.assertEqual([(p["op"], p["path"]) for p in plan.patch], [("test", "/metadata/uid"), ("test", "/metadata/resourceVersion"), ("replace", "/data/.dockerconfigjson")])
        self.assertEqual(plan.patch[1]["value"], "opaque-original-version")

    def test_expiry_requires_two_hours_and_aware_sdk_datetime(self):
        build_plan(secret(), authorization(ttl=7200), UID, NOW)
        for ttl in (7199, 0, -1):
            with self.subTest(ttl=ttl), self.assertRaisesRegex(ValidationError, "^authorization_expiry$"):
                build_plan(secret(), authorization(ttl=ttl), UID, NOW)
        for expiry in (datetime.datetime(2027, 1, 1), NOW + 43200, "2027-01-01T00:00:00Z", None):
            response = authorization()
            response["authorizationData"][0]["expiresAt"] = expiry
            with self.subTest(expiry=expiry), self.assertRaisesRegex(ValidationError, "^authorization_expiry$"):
                build_plan(secret(), response, UID, NOW)

    def test_authorization_requires_single_exact_endpoint(self):
        for data in (None, [], [{}, {}], {}):
            with self.subTest(data=data), self.assertRaisesRegex(ValidationError, "^authorization_shape$"):
                build_plan(secret(), {"authorizationData": data}, UID, NOW)
        for endpoint in ("http://" + REGISTRY, "https://" + REGISTRY + "/", "https://other.example.invalid", None):
            response = authorization()
            response["authorizationData"][0]["proxyEndpoint"] = endpoint
            with self.subTest(endpoint=endpoint), self.assertRaisesRegex(ValidationError, "^authorization_endpoint$"):
                build_plan(secret(), response, UID, NOW)

    def test_authorization_rejects_bad_tokens_with_static_errors(self):
        tokens = ("sensitive-invalid!", base64.b64encode(b"OTHER:sensitive").decode(), base64.b64encode(b"AWS:").decode(), base64.b64encode(b"AWS").decode(), base64.b64encode(b"AWS:\xff").decode(), None)
        for token in tokens:
            response = authorization()
            response["authorizationData"][0]["authorizationToken"] = token
            with self.subTest(token=token), self.assertRaisesRegex(ValidationError, "^authorization_token$"):
                build_plan(secret(), response, UID, NOW)

    def test_nonfinite_or_boolean_clock_is_rejected(self):
        for now in (float("nan"), float("inf"), 10**1000, True, None):
            with self.subTest(now=now), self.assertRaisesRegex(ValidationError, "^clock$"):
                build_plan(secret(), authorization(), UID, now)

    def test_readback_rejects_recreated_uid_unchanged_version_or_mutability(self):
        plan = build_plan(secret(), authorization(), UID, NOW)
        after = readback(plan)
        after["metadata"]["uid"] = "recreated-uid"
        with self.assertRaisesRegex(ValidationError, "^secret_identity$"):
            verify_readback(plan, after)
        after = readback(plan)
        after["metadata"]["resourceVersion"] = plan.resource_version
        with self.assertRaisesRegex(ValidationError, "^readback_resource_version$"):
            verify_readback(plan, after)
        after = readback(plan)
        del after["immutable"]
        with self.assertRaisesRegex(ValidationError, "^readback_mutability$"):
            verify_readback(plan, after)

    def test_readback_detects_other_data_or_registry_mutation(self):
        plan = build_plan(secret(), authorization(), UID, NOW)
        after = readback(plan)
        after["data"]["other-key"] = encoded("changed")
        with self.assertRaisesRegex(ValidationError, "^readback_data$"):
            verify_readback(plan, after)
        after = readback(plan)
        document = strict_json(base64.b64decode(after["data"][".dockerconfigjson"]))
        document["auths"]["other.example.invalid"]["auth"] = "changed"
        after["data"][".dockerconfigjson"] = encoded(document)
        with self.assertRaisesRegex(ValidationError, "^readback_data$"):
            verify_readback(plan, after)


if __name__ == "__main__":
    unittest.main()

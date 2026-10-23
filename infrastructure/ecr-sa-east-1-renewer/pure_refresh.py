"""Pure validation and CAS planning for one existing ECR pull Secret.

This module performs no I/O. Credential values belong only in caller memory.
"""

import base64
import binascii
import copy
import datetime
import json
import math
from dataclasses import dataclass


NAMESPACE = "dakasa"
SECRET_NAME = "ecr-pull-sa-east-1"
REGISTRY = "153828470928.dkr.ecr.sa-east-1.amazonaws.com"
MIN_TOKEN_TTL_SECONDS = 7200
_DOCKER_KEY = ".dockerconfigjson"
_SECRET_TYPE = "kubernetes.io/dockerconfigjson"


class ValidationError(ValueError):
    """A static validation label, containing no response or credential value."""


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("json_duplicate_key")
        result[key] = value
    return result


def _nonfinite(_value):
    raise ValidationError("json_nonfinite")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValidationError("json_nonfinite")
    return number


def strict_json(raw: bytes) -> dict:
    """Decode a JSON object without silently discarding duplicate keys."""
    if type(raw) is not bytes:
        raise ValidationError("json_bytes_required")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object,
            parse_constant=_nonfinite,
            parse_float=_finite_float,
        )
    except ValidationError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise ValidationError("json_invalid") from None
    if type(value) is not dict:
        raise ValidationError("json_object_required")
    return value


def _nonempty_string(value):
    return type(value) is str and bool(value)


def _decode_base64(value, label):
    if not _nonempty_string(value):
        raise ValidationError(label)
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ValidationError(label) from None


def _secret_document(before, expected_uid):
    if not _nonempty_string(expected_uid):
        raise ValidationError("expected_uid_required")
    if type(before) is not dict:
        raise ValidationError("secret_shape")
    metadata = before.get("metadata")
    if type(metadata) is not dict:
        raise ValidationError("secret_shape")
    if (
        before.get("kind") != "Secret"
        or before.get("apiVersion") != "v1"
        or metadata.get("name") != SECRET_NAME
        or metadata.get("namespace") != NAMESPACE
        or metadata.get("uid") != expected_uid
        or not _nonempty_string(metadata.get("resourceVersion"))
    ):
        raise ValidationError("secret_identity")
    if (
        metadata.get("deletionTimestamp") is not None
        or metadata.get("deletionGracePeriodSeconds") is not None
    ):
        raise ValidationError("secret_deleting")
    if before.get("type") != _SECRET_TYPE:
        raise ValidationError("secret_type")
    immutable = before.get("immutable")
    if immutable is not None and immutable is not False:
        raise ValidationError("secret_immutable")
    data = before.get("data")
    if type(data) is not dict or any(
        type(key) is not str or type(value) is not str for key, value in data.items()
    ):
        raise ValidationError("secret_data")
    raw = _decode_base64(data.get(_DOCKER_KEY), "dockerconfig_base64")
    document = strict_json(raw)
    auths = document.get("auths")
    if type(auths) is not dict:
        raise ValidationError("dockerconfig_auths")
    entry = auths.get(REGISTRY)
    if type(entry) is not dict or not _nonempty_string(entry.get("auth")):
        raise ValidationError("dockerconfig_entry")
    return document


def validate_before(before: dict, expected_uid: str) -> None:
    _secret_document(before, expected_uid)


@dataclass(frozen=True, repr=False)
class Plan:
    before: dict
    patch: list
    expires_at: float
    expected_encoded: str
    uid: str
    resource_version: str


def build_plan(before, authorization_response, expected_uid, now: float) -> Plan:
    document = _secret_document(before, expected_uid)
    if type(now) not in (int, float):
        raise ValidationError("clock")
    try:
        now = float(now)
    except (OverflowError, ValueError):
        raise ValidationError("clock") from None
    if not math.isfinite(now):
        raise ValidationError("clock")
    if type(authorization_response) is not dict:
        raise ValidationError("authorization_shape")
    authorization_data = authorization_response.get("authorizationData")
    if (
        type(authorization_data) is not list
        or len(authorization_data) != 1
        or type(authorization_data[0]) is not dict
    ):
        raise ValidationError("authorization_shape")
    authorization = authorization_data[0]
    if authorization.get("proxyEndpoint") != "https://" + REGISTRY:
        raise ValidationError("authorization_endpoint")
    expiry = authorization.get("expiresAt")
    if not isinstance(expiry, datetime.datetime):
        raise ValidationError("authorization_expiry")
    try:
        if expiry.tzinfo is None or expiry.utcoffset() is None:
            raise ValidationError("authorization_expiry")
        expires_at = expiry.timestamp()
    except (OverflowError, OSError, ValueError):
        raise ValidationError("authorization_expiry") from None
    if not math.isfinite(expires_at) or expires_at - now < MIN_TOKEN_TTL_SECONDS:
        raise ValidationError("authorization_expiry")
    token = authorization.get("authorizationToken")
    decoded = _decode_base64(token, "authorization_token")
    username, separator, password_bytes = decoded.partition(b":")
    if username != b"AWS" or not separator or not password_bytes:
        raise ValidationError("authorization_token")
    try:
        password = password_bytes.decode("utf-8")
    except UnicodeError:
        raise ValidationError("authorization_token") from None

    updated = copy.deepcopy(document)
    entry = updated["auths"][REGISTRY]
    entry["auth"] = token
    if "username" in entry:
        entry["username"] = "AWS"
    if "password" in entry:
        entry["password"] = password
    expected_encoded = base64.b64encode(
        json.dumps(updated, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).decode("ascii")
    resource_version = before["metadata"]["resourceVersion"]
    patch = [
        {"op": "test", "path": "/metadata/uid", "value": expected_uid},
        {
            "op": "test",
            "path": "/metadata/resourceVersion",
            "value": resource_version,
        },
        {"op": "replace", "path": "/data/.dockerconfigjson", "value": expected_encoded},
    ]
    return Plan(
        before=copy.deepcopy(before),
        patch=patch,
        expires_at=expires_at,
        expected_encoded=expected_encoded,
        uid=expected_uid,
        resource_version=resource_version,
    )


def verify_readback(plan, after) -> None:
    validate_before(after, plan.uid)
    if after["metadata"]["resourceVersion"] == plan.resource_version:
        raise ValidationError("readback_resource_version")
    if after.get("immutable") != plan.before.get("immutable"):
        raise ValidationError("readback_mutability")
    expected_data = copy.deepcopy(plan.before["data"])
    expected_data[_DOCKER_KEY] = plan.expected_encoded
    if after["data"] != expected_data:
        raise ValidationError("readback_data")

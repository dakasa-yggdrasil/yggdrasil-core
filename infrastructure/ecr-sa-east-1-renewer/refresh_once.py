"""Source-only: one admitted refresh; imports never contact a service."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import math
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

# The principal must install reviewed source in an owner-controlled directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from pure_refresh import (NAMESPACE, SECRET_NAME, REGISTRY, ValidationError,
                          strict_json, validate_before, build_plan, verify_readback, MIN_TOKEN_TTL_SECONDS)


class Hold(RuntimeError):
    """Static PUBLIC reason only; never include an HTTP body or credentials."""


class TransportFailure(RuntimeError):
    def __init__(self, status=None):
        super().__init__("transport_failure")
        self.status = status


class CycleFailure(RuntimeError):
    def __init__(self, public_result):
        super().__init__("patch_result_unconfirmed")
        self.public_result = public_result


def private_read(path, limit=2 << 20):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise Hold("private_file_ownership_or_mode")
        raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise Hold("private_file_limit")
        return raw


def trusted_path(path):
    """Reject symlinks and untrusted writable ancestors before sensitive IO."""
    p = Path(path)
    if not p.is_absolute() or ".." in p.parts:
        raise Hold("absolute_trusted_path_required")
    for part in [p] + list(p.parents):
        info = part.lstat()
        if (stat.S_ISLNK(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or stat.S_IMODE(info.st_mode) & 0o022):
            raise Hold("untrusted_path")
    return p


PROJECTED_FILES = {
    "/etc/dakasa-ecr/admission.json": "/etc/dakasa-ecr",
    "/var/run/secrets/dakasa-ecr/token": "/var/run/secrets/dakasa-ecr",
    "/var/run/secrets/dakasa-ecr/ca.crt": "/var/run/secrets/dakasa-ecr",
}

PROJECTED_CANONICAL_ROOTS = {
    "/etc/dakasa-ecr": "/etc/dakasa-ecr",
    "/var/run/secrets/dakasa-ecr": "/run/secrets/dakasa-ecr",
}


def _projected_path(root, actual):
    # Only the fixed projection root may have writable mode bits. A read-only
    # mount makes those bits ineffective; all other path checks stay strict.
    if (root not in {Path(value) for value in PROJECTED_CANONICAL_ROOTS.values()}
            or root not in actual.parents):
        raise Hold("projection_escaped_mount")
    trusted_path(root.parent)
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())):
        raise Hold("untrusted_projection_root")
    if not os.statvfs(root).f_flag & os.ST_RDONLY:
        raise Hold("projection_mount_not_readonly")
    device = info.st_dev
    for part in [actual] + list(actual.parents):
        if part == root:
            break
        info = part.lstat()
        if (stat.S_ISLNK(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or stat.S_IMODE(info.st_mode) & 0o022):
            raise Hold("untrusted_path")
        if (info.st_dev != device or not os.statvfs(part).f_flag & os.ST_RDONLY):
            raise Hold("projection_mount_mismatch")
        if not (stat.S_ISREG(info.st_mode) if part == actual else stat.S_ISDIR(info.st_mode)):
            raise Hold("projection_path_type")
    return actual


def input_path(path):
    # Kubelet projections use symlinks for atomic rotation. Only these fixed
    # mounts may resolve symlinks, and their targets must stay inside the mount.
    if path in PROJECTED_FILES:
        root = Path(PROJECTED_FILES[path]).resolve(strict=True)
        if root != Path(PROJECTED_CANONICAL_ROOTS[PROJECTED_FILES[path]]):
            raise Hold("projection_mount_root_mismatch")
        actual = Path(path).resolve(strict=True)
        if root not in actual.parents:
            raise Hold("projection_escaped_mount")
        return _projected_path(root, actual)
    return trusted_path(path)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise TransportFailure()


def exchange(url, method="GET", headers=None, body=None, context=None, limit=2 << 20):
    handlers = [urllib.request.ProxyHandler({}), NoRedirect()]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with opener.open(request, timeout=6) as response:
            if response.status != 200:
                raise TransportFailure(response.status)
            raw = response.read(limit + 1)
            if len(raw) > limit:
                raise TransportFailure()
            return raw
    except urllib.error.HTTPError as error:
        status_code = error.code
        error.close()
        raise TransportFailure(status_code) from None
    except (OSError, urllib.error.URLError, ValueError):
        raise TransportFailure() from None


class KubeSecret:
    def __init__(self, config):
        self.url = config["kube_server"] + "/api/v1/namespaces/" + NAMESPACE + "/secrets/" + SECRET_NAME
        self.token_file = config["kube_token_file"]
        self.context = ssl.create_default_context(cafile=str(input_path(config["kube_ca_file"])))

    def request(self, method, value=None):
        # Re-open the existing, externally rotated credential each request.
        token = private_read(input_path(self.token_file), 65536).decode("ascii").strip()
        if not re.fullmatch(r"[A-Za-z0-9._~-]+", token):
            raise Hold("kube_token_invalid")
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        body = None
        if value is not None:
            headers["Content-Type"] = "application/json-patch+json"
            body = json.dumps(value, separators=(",", ":"), allow_nan=False).encode()
        return exchange(self.url, method, headers, body, self.context)

    def get_secret(self):
        return strict_json(self.request("GET"))

    def patch_secret(self, patch):
        # Consume and discard the response in RAM. A separate GET verifies state.
        self.request("PATCH", patch)


class HostECR:
    def __init__(self, config):
        self.config = config

    def authorization(self):
        c = self.config
        base = "http://169.254.169.254/latest/"
        token = exchange(base + "api/token", "PUT",
                         {"X-aws-ec2-metadata-token-ttl-seconds": "60"}, limit=65536).decode("ascii")
        if not token or "\n" in token or "\r" in token:
            raise Hold("imds_token_invalid")
        headers = {"X-aws-ec2-metadata-token": token}
        instance = exchange(base + "meta-data/instance-id", headers=headers, limit=256).decode("ascii").strip()
        info = strict_json(exchange(base + "meta-data/iam/info", headers=headers, limit=65536))
        role = exchange(base + "meta-data/iam/security-credentials/", headers=headers, limit=512).decode("ascii").strip()
        if (instance != c["expected_instance_id"] or info.get("Code") != "Success"
                or info.get("InstanceProfileArn") != c["existing_instance_profile_arn"]
                or role != c["existing_role_name"]):
            raise Hold("host_identity_changed")
        credentials = strict_json(exchange(base + "meta-data/iam/security-credentials/" + role,
                                            headers=headers, limit=65536))
        try:
            expiry = dt.datetime.fromisoformat(credentials["Expiration"].replace("Z", "+00:00"))
            valid_expiry = expiry.utcoffset() is not None and expiry.timestamp() > time.time() + 300
        except (KeyError, TypeError, ValueError, AttributeError):
            valid_expiry = False
        if (credentials.get("Code") != "Success" or not valid_expiry
                or any(not isinstance(credentials.get(k), str) or not credentials[k]
                       for k in ("AccessKeyId", "SecretAccessKey", "Token"))):
            raise Hold("imds_credentials_invalid")
        # No default credential provider, local profile, container endpoint or process.
        # These imports occur only after admission and explicit IMDSv2 validation.
        import boto3
        import botocore.session
        from botocore.config import Config
        session = botocore.session.Session()
        session.set_config_variable("config_file", os.devnull)
        session.set_config_variable("credentials_file", os.devnull)
        client = boto3.Session(botocore_session=session).client(
            "ecr", region_name="sa-east-1", endpoint_url="https://api.ecr.sa-east-1.amazonaws.com",
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["Token"], verify=True,
            config=Config(signature_version="v4", connect_timeout=3, read_timeout=6,
                          retries={"total_max_attempts": 1, "mode": "standard"},
                          proxies={}, ignore_configured_endpoint_urls=True))
        try:
            # registryIds is deprecated and is not an IAM scope control.
            return client.get_authorization_token()
        finally:
            client.close()
            credentials.clear()


def run_cycle(kube, ecr, expected_uid, clock=time.time):
    attempt = uuid.uuid4().hex
    before = kube.get_secret()
    validate_before(before, expected_uid)
    plan = build_plan(before, ecr.authorization(), expected_uid, clock())
    current = clock()
    if not math.isfinite(current) or plan.expires_at < current + MIN_TOKEN_TTL_SECONDS:
        raise Hold("expiry_margin_lost_before_patch")
    if plan.expected_encoded == before["data"][".dockerconfigjson"]:
        return {"attempt": attempt, "uid": plan.uid, "status": "NO_PATCH_ALREADY_CURRENT",
                "expires_at_epoch": plan.expires_at, "patch_transport": "not_sent"}
    transport = "acknowledged"
    http_status = 200
    try:
        kube.patch_secret(plan.patch)
    except TransportFailure as error:
        http_status = error.status
        if error.status is not None and error.status < 500:
            raise CycleFailure({"attempt": attempt, "uid": plan.uid,
                                "status": "PATCH_HTTP_ERROR", "patch_attempted": True,
                                "patch_transport": "http_error", "patch_http_status": http_status}) from None
        transport = "uncertain"
    # Never resend in this Job. A later Job obtains a fresh Secret/token/plan.
    # Late old and new requests must both pass UID/RV CAS: only one can win.
    try:
        after = kube.get_secret()
        verify_readback(plan, after)
        current = clock()
        if not math.isfinite(current) or plan.expires_at < current + MIN_TOKEN_TTL_SECONDS:
            raise Hold("expiry_margin_lost_after_patch")
    except Exception:
        raise CycleFailure({"attempt": attempt, "uid": plan.uid,
                            "status": "PATCH_RESULT_UNCONFIRMED", "patch_attempted": True,
                            "patch_transport": transport, "patch_http_status": http_status}) from None
    return {"attempt": attempt, "uid": plan.uid,
            "before_rv": plan.resource_version,
            "after_rv": after["metadata"]["resourceVersion"],
            "expires_at_epoch": plan.expires_at, "state_exactly_observed": True,
            "patch_attempted": True, "patch_transport": transport, "patch_http_status": http_status,
            "status": ("REFRESH_CONFIRMED" if transport == "acknowledged"
                       else "STATE_OBSERVED_AFTER_UNCERTAIN_PATCH")}


REQUIRED = {
    "approved_by_principal", "existing_host_role_multiservice_use_accepted",
    "existing_ecr_read_only_scope_observed", "host_imds_v2_available_confirmed",
    "kube_single_secret_scope_confirmed", "projected_serviceaccount_rotation_selected",
    "public_identity_evidence_ref", "public_kube_evidence_ref", "existing_principal_arn",
    "existing_instance_profile_arn", "existing_role_name", "expected_instance_id",
    "expected_secret_uid", "execution_target", "scheduler", "kube_identity",
    "kube_server", "kube_ca_file", "kube_token_file"}

APPROVAL_FLAGS = {
    "approved_by_principal", "existing_host_role_multiservice_use_accepted",
    "existing_ecr_read_only_scope_observed", "host_imds_v2_available_confirmed",
    "kube_single_secret_scope_confirmed", "projected_serviceaccount_rotation_selected"}


def admit(c, check_files=True):
    if not isinstance(c, dict) or set(c) != REQUIRED:
        raise Hold("admission_schema")
    flags = APPROVAL_FLAGS
    if any(c[k] is not True for k in flags):
        raise Hold("fresh_principal_admission_required")
    if any(not isinstance(c[k], str) or not c[k].strip() for k in REQUIRED - flags):
        raise Hold("unknown_fact")
    if (c["execution_target"] != "existing_brain_host_network_pod"
            or c["scheduler"] != "kubernetes_cronjob"
            or not re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", c["existing_role_name"])
            or not re.fullmatch(r"i-[0-9a-f]{17}", c["expected_instance_id"])
            or not re.fullmatch(r"arn:aws:iam::[0-9]{12}:instance-profile/[A-Za-z0-9+=,.@_/-]+",
                                c["existing_instance_profile_arn"])
            or not re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+",
                                c["existing_principal_arn"])
            or c["existing_principal_arn"].rsplit("/", 1)[-1] != c["existing_role_name"]):
        raise Hold("identity_or_execution_target")
    try:
        if str(uuid.UUID(c["expected_secret_uid"])) != c["expected_secret_uid"]:
            raise ValueError()
    except ValueError:
        raise Hold("fresh_secret_uid_required") from None
    server = urllib.parse.urlsplit(c["kube_server"])
    if (server.scheme != "https" or not server.hostname or server.username or server.password
            or server.path or server.query or server.fragment):
        raise Hold("kube_https_origin_required")
    if (c["kube_ca_file"] != "/var/run/secrets/dakasa-ecr/ca.crt"
            or c["kube_token_file"] != "/var/run/secrets/dakasa-ecr/token"):
        raise Hold("fixed_projected_credentials_required")
    if check_files:
        for key in ("kube_ca_file", "kube_token_file"):
            input_path(c[key])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admission", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    try:
        if any(k.startswith("AWS_") or k in ("BOTO_CONFIG", "HTTP_PROXY", "HTTPS_PROXY",
               "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy") for k in os.environ):
            raise Hold("ambient_cloud_configuration_forbidden")
        config = strict_json(private_read(input_path(args.admission)))
        admit(config)
        result = run_cycle(KubeSecret(config), HostECR(config), config["expected_secret_uid"])
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return 0 if result["status"] in ("REFRESH_CONFIRMED", "NO_PATCH_ALREADY_CURRENT") else 78
    except CycleFailure as error:
        print(json.dumps(error.public_result, sort_keys=True, allow_nan=False))
        return 78
    except Exception as error:
        print(json.dumps({"status": "HOLD", "error_class": type(error).__name__,
                          "reason": str(error) if isinstance(error, Hold) else "operation_failed"}))
        return 78


if __name__ == "__main__":
    sys.exit(main())

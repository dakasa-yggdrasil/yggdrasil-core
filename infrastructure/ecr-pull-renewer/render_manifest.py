"""Local-only renderer. Writes a suspended manifest; never contacts Kubernetes."""
import argparse
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pure_refresh import strict_json
from refresh_once import admit


def public_pinned_image(value):
    # Public accessibility still requires Root verification. Restrict the
    # candidate registries so alternate private ECR endpoints cannot slip in.
    return (bool(re.fullmatch(r"[a-z0-9][a-z0-9._:/-]+@sha256:[0-9a-f]{64}", value))
            and value.split("/", 1)[0] in ("docker.io", "ghcr.io", "public.ecr.aws"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admission", required=True)
    parser.add_argument("--image", required=True, help="Root-reviewed public image by sha256 digest")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not public_pinned_image(args.image):
        parser.error("public immutable image required; target private ECR is forbidden")
    config = strict_json(Path(args.admission).read_bytes())
    admit(config, check_files=False)
    if config["kube_identity"] != "system:serviceaccount:dakasa:ecr-pull-renewer":
        parser.error("identity must match the reviewed dedicated ServiceAccount")
    document = strict_json((Path(__file__).resolve().parent / "KUBERNETES.TEMPLATE.json").read_bytes())
    config_map = next(x for x in document["items"] if x["kind"] == "ConfigMap")
    config_map["data"]["admission.json"] = json.dumps(config, sort_keys=True, allow_nan=False)
    cron = next(x for x in document["items"] if x["kind"] == "CronJob")
    cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]["image"] = args.image
    if cron["spec"]["suspend"] is not True:
        raise ValueError("suspended_manifest_required")
    with open(args.output, "x") as stream:
        json.dump(document, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print("Suspended manifest rendered locally; public accessibility is a Root verification.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

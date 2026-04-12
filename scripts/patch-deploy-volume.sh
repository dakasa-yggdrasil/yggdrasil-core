#!/bin/bash
# patch-deploy-volume.sh — adds the hostPath volume mount for /repos so
# Yggdrasil can read kustomize overlays from the local repo checkout.
#
# Run once on the EC2 after deploying the Yggdrasil pod:
#   bash scripts/patch-deploy-volume.sh
#
# The deployment will restart with the /repos volume mounted read-only.

set -euo pipefail

NAMESPACE="${NAMESPACE:-dakasa}"
DEPLOYMENT="${DEPLOYMENT:-yggdrasil}"
KUBECTL="${KUBECTL:-sudo k3s kubectl}"

echo "Patching deployment ${NAMESPACE}/${DEPLOYMENT} with /repos hostPath volume..."

${KUBECTL} patch deployment "${DEPLOYMENT}" -n "${NAMESPACE}" --type=json -p='[
  {
    "op": "add",
    "path": "/spec/template/spec/volumes/-",
    "value": {
      "name": "repos",
      "hostPath": {
        "path": "/home/ubuntu/dakasa-system",
        "type": "Directory"
      }
    }
  },
  {
    "op": "add",
    "path": "/spec/template/spec/containers/0/volumeMounts/-",
    "value": {
      "name": "repos",
      "mountPath": "/repos",
      "readOnly": true
    }
  }
]'

echo "Waiting for rollout..."
${KUBECTL} rollout status deployment/"${DEPLOYMENT}" -n "${NAMESPACE}" --timeout=120s

echo "Done. Verify with:"
echo "  ${KUBECTL} exec -n ${NAMESPACE} deploy/${DEPLOYMENT} -- ls /repos/"

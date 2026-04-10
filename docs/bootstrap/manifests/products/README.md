# Bootstrap product manifests

These manifests are the canonical bootstrap source material for platform products in
`yggdrasil-core`.

Imported manifests:

- `certificate-cert-manager.json` from `certificate/cert-manager`
- `mesh-istio-continuous-deployment-argo-cd.json` from `mesh/istio/continuous-deployment/argo-cd`
- `mesh-istio-observability-jaeger.json` from `mesh/istio/observability/jaeger`
- `mesh-istio-observability-kiali.json` from `mesh/istio/observability/kiali`
- `message-broker-rabbitmq.json` from `message-broker/rabbitmq`
- `observability-alloy.json` from `observability/alloy`
- `observability-grafana.json` from `observability/grafana`
- `observability-loki.json` from `observability/loki`
- `observability-prometheus.json` from `observability/prometheus`
- `strategy-deployment-argo-rollouts.json` from `strategy-deployment/argo-rollouts`

Bootstrap rules applied:

- each product uses `source.kind = inline`
- each product uses `renderer.kind = raw_k8s`
- each product targets `integration_instance_ref = { name: "kubernetes-default", namespace: "global" }`

These manifests are bootstrap assets. They can be curated over time into cleaner Git-native
products as the platform matures.

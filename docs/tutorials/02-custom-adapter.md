# Tutorial 2 — Build a Custom Integration Adapter

**Time:** ~60 minutes.
**Outcome:** Yggdrasil dispatches a workflow step to a system Yggdrasil did not previously know about — illustrated here with a tiny "Datadog event" adapter that posts an event to Datadog from a workflow step.

## Why custom adapters

Yggdrasil ships eight adapters (kubernetes, github, aws, rabbitmq, grafana, secrets-management, database-admin, kustomize). Whenever your workflow needs to talk to a system not in that list — Datadog, PagerDuty, internal metering, an audit service, a homegrown registry — you write a small Go (or any language) HTTP service that exposes two endpoints (`/rpc/describe` and `/rpc/execute`) and register it as an `integration_type` + `integration_instance` pair.

## Architecture

```
yggdrasil-core ──HTTP/JSON──▶ your adapter (port 8081)
                                  │
                                  ├─ POST /rpc/describe  →  capability metadata
                                  └─ POST /rpc/execute   →  capability invocation
```

Adapters are stateless service objects. They speak the same wire protocol as the bundled adapters; the core does not care if the adapter is in Go, Python, or shell, as long as it answers correctly.

## Step 1 — Scaffold

Clone the integration template:

```bash
git clone https://github.com/dakasa-yggdrasil/integration-template my-datadog-adapter
cd my-datadog-adapter
```

The template ships:

- `cmd/server/main.go` — entry point with HTTP listener and `/rpc/{describe,execute}` routes
- `internal/adapter/spec.go` — the `Describe()` and `Execute()` implementations you fill in
- `Dockerfile` and `release.yml` GHA workflow ready to publish to ghcr
- `go.mod` with `yggdrasil-sdk-go` already imported

## Step 2 — Define your capability in `Describe()`

Open `internal/adapter/spec.go`. Replace `Describe()` with:

```go
func (a *Adapter) Describe() sdk.DescribeResponse {
    return sdk.DescribeResponse{
        Family:  "observability",
        Type:    "datadog",
        Version: "v0.1.0",
        Capabilities: []sdk.Capability{
            {
                Name:        "post_event",
                Description: "Post an event to Datadog Events API",
                Inputs: map[string]sdk.InputSpec{
                    "title":     {Type: "string", Required: true},
                    "text":      {Type: "string", Required: true},
                    "priority":  {Type: "string", Required: false},  // "normal" | "low"
                    "alert_type": {Type: "string", Required: false}, // "info" | "warning" | "error"
                    "tags":      {Type: "array", Required: false},
                },
                Outputs: map[string]sdk.OutputSpec{
                    "event_id": {Type: "string"},
                    "url":      {Type: "string"},
                },
            },
        },
    }
}
```

`Describe()` is what the core calls when an `integration_instance` is registered or when `/api/v1/integration-runtime-states` queries adapter health. The shape of the response **must** match the seeded `integration_type` manifest, otherwise the runtime state reports `contract_mismatch`.

## Step 3 — Implement `Execute()`

```go
func (a *Adapter) Execute(ctx context.Context, req sdk.ExecuteRequest) (sdk.ExecuteResponse, error) {
    if req.Capability != "post_event" {
        return sdk.ExecuteResponse{}, fmt.Errorf("unknown capability %q", req.Capability)
    }

    apiKey := os.Getenv("DATADOG_API_KEY")
    if apiKey == "" {
        return sdk.ExecuteResponse{}, fmt.Errorf("DATADOG_API_KEY is not set")
    }

    body := map[string]any{
        "title":      req.Inputs["title"],
        "text":       req.Inputs["text"],
        "priority":   req.Inputs["priority"],
        "alert_type": req.Inputs["alert_type"],
        "tags":       req.Inputs["tags"],
    }
    payload, _ := json.Marshal(body)

    httpReq, err := http.NewRequestWithContext(ctx, "POST",
        "https://api.datadoghq.com/api/v1/events", bytes.NewReader(payload))
    if err != nil {
        return sdk.ExecuteResponse{}, err
    }
    httpReq.Header.Set("Content-Type", "application/json")
    httpReq.Header.Set("DD-API-KEY", apiKey)

    resp, err := http.DefaultClient.Do(httpReq)
    if err != nil {
        return sdk.ExecuteResponse{}, fmt.Errorf("datadog post: %w", err)
    }
    defer resp.Body.Close()
    if resp.StatusCode >= 300 {
        msg, _ := io.ReadAll(resp.Body)
        return sdk.ExecuteResponse{}, fmt.Errorf("datadog returned %d: %s", resp.StatusCode, msg)
    }

    var ddResp struct {
        Event struct {
            ID  int64  `json:"id"`
            URL string `json:"url"`
        } `json:"event"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&ddResp); err != nil {
        return sdk.ExecuteResponse{}, err
    }

    return sdk.ExecuteResponse{
        Status: "succeeded",
        Metadata: map[string]any{
            "event_id": fmt.Sprint(ddResp.Event.ID),
            "url":      ddResp.Event.URL,
        },
    }, nil
}
```

## Step 4 — Build and push

```bash
docker build -t ghcr.io/<you>/integration-datadog:v0.1.0 .
docker push ghcr.io/<you>/integration-datadog:v0.1.0
```

(Or trust the bundled `release.yml`: tag the repo `v0.1.0` and let GHA publish.)

## Step 5 — Deploy the adapter to your cluster

```yaml
# adapter-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata: {name: integration-datadog-adapter, namespace: yggdrasil}
spec:
  replicas: 1
  selector: {matchLabels: {app: integration-datadog-adapter}}
  template:
    metadata: {labels: {app: integration-datadog-adapter}}
    spec:
      containers:
      - name: adapter
        image: ghcr.io/<you>/integration-datadog:v0.1.0
        ports: [{containerPort: 8081}]
        env:
        - {name: DATADOG_API_KEY, valueFrom: {secretKeyRef: {name: datadog-creds, key: api-key}}}
---
apiVersion: v1
kind: Service
metadata: {name: integration-datadog-adapter, namespace: yggdrasil}
spec:
  selector: {app: integration-datadog-adapter}
  ports: [{port: 8081, targetPort: 8081}]
```

```bash
kubectl create secret generic datadog-creds -n yggdrasil --from-literal=api-key=<your-dd-api-key>
kubectl apply -f adapter-deployment.yaml
kubectl -n yggdrasil rollout status deployment/integration-datadog-adapter
```

## Step 6 — Register integration_type

```json
{
  "name": "datadog",
  "namespace": "global",
  "description": "Datadog adapter — posts events from workflow steps",
  "spec": {
    "family": "observability",
    "transport": "http_json",
    "capabilities": [
      {
        "name": "post_event",
        "description": "Post an event to Datadog Events API",
        "inputs": {"title": {"type": "string", "required": true}, "text": {"type": "string", "required": true}, "priority": {"type": "string"}, "alert_type": {"type": "string"}, "tags": {"type": "array"}},
        "outputs": {"event_id": {"type": "string"}, "url": {"type": "string"}}
      }
    ]
  }
}
```

```bash
curl -sf -X POST -H "Content-Type: application/json" \
  "$YGG_URL/api/v1/manifests?kind=integration_type" \
  -d @datadog-type.json
```

## Step 7 — Register integration_instance

```json
{
  "name": "datadog-prod",
  "namespace": "global",
  "spec": {
    "type_ref": {"namespace": "global", "name": "datadog"},
    "status": "active",
    "config": {"base_url": "http://integration-datadog-adapter.yggdrasil.svc.cluster.local:8081"},
    "execution": {"max_batch_size": 1}
  }
}
```

```bash
curl -sf -X POST -H "Content-Type: application/json" \
  "$YGG_URL/api/v1/integration-instances" \
  -d @datadog-instance.json
```

## Step 8 — Verify handshake

```bash
curl -sf "$YGG_URL/api/v1/integration-runtime-states?namespace=global&name=datadog-prod" | jq '.runtime_states[] | {check_kind, status}'
```

Both `describe_handshake` and `transport_connectivity` should report `status: healthy`. If `contract_mismatch`, the `details.diff` field tells you exactly which field of `Describe()` does not match the registered `integration_type` manifest — adjust either side and retry.

## Step 9 — Use it in a workflow

```json
{
  "name": "alert-on-deploy",
  "namespace": "default",
  "spec": {
    "trigger": {"mode": "manual"},
    "input_schema": {"required": ["service", "version"]},
    "steps": [
      {
        "id": "post",
        "use": {
          "kind": "integration",
          "instance_ref": {"namespace": "global", "name": "datadog-prod"},
          "capability": "post_event"
        },
        "with": {
          "title": "{{ inputs.service }} deployed",
          "text": "Version {{ inputs.version }} deployed to production",
          "alert_type": "info",
          "tags": ["env:prod", "service:{{ inputs.service }}"]
        }
      }
    ]
  }
}
```

POST it; run it; observe in Datadog Events.

## What you accomplished

- Built a custom adapter from scratch in ~60 minutes using `yggdrasil-sdk-go`.
- Registered it with the core via two manifest POSTs (no code change in `yggdrasil-core`).
- Used it from a workflow with templating.

## Next

- The same pattern applies for any external system. Replace `Datadog` with `your_system`, ship one adapter per system, and Yggdrasil orchestrates them all in workflows.
- Production adapters add **retry**, **rate limiting**, **structured logging**, and **graceful shutdown**. The template includes scaffolds for each.
- Read [features/integrations.md](../features/integrations.md) for the full integration model.

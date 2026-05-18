# Integration Surfaces — Phase 0d: Deploy Template Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the kustomize-based deploy template that each Phase 1 integration surface will copy. Validate end-to-end with a placeholder surface (`surface-placeholder`) before any real surface tries to deploy.

**Architecture:** Each `integration-<name>` repo gains a `deploy/surface-base/` folder (parallel to its existing `deploy/base/` for the adapter) containing `deployment.yaml`, `service.yaml`, `ingress.yaml`, `kustomization.yaml` for the surface SPA Docker image. A shared `strip-surface-prefix` Traefik Middleware CRD lives in `surface-template/deploy/` and is applied once cluster-wide. ForwardAuth middleware (existing for surface-console) is reused.

**Tech Stack:** Kubernetes manifests (apps/v1, v1, networking.k8s.io/v1), Traefik Middleware CRD (traefik.io/v1alpha1), kustomize, Yggdrasil workflow for apply.

**Spec reference:** §7.5–7.6.

**Working directories:**
- Template authoring: `/Users/dakasa/projects/yggdrasil/surface-template/`
- Placeholder surface: NEW repo `/Users/dakasa/projects/yggdrasil/surface-placeholder/` (created in Task 4)

**Commit cadence:** push direct to `main`. No co-author trailers.

---

## Task 1: Inspect existing deploy patterns

**Files:** none (read-only)

- [ ] **Step 1: Catalog existing deploy structures across active repos**

```bash
find /Users/dakasa/projects -maxdepth 5 -name "ingress.yaml" -path "*deploy/base*" 2>/dev/null
find /Users/dakasa/projects -maxdepth 5 -name "*.yaml" -path "*Middleware*" 2>/dev/null
find /Users/dakasa/projects -maxdepth 5 -name "*forwardauth*" 2>/dev/null
```

Expected outputs reveal: tartaro-fe, dakasa-orchestrator, dakasa-enterprise-rta-api, and others use `networking.k8s.io/v1 Ingress` with `ingressClassName: traefik` annotations.

- [ ] **Step 2: Inspect tartaro-fe deploy/base/ as the canonical example**

```bash
cat /Users/dakasa/projects/dakasa/dakasa-tartaro-fe/deploy/base/ingress.yaml
cat /Users/dakasa/projects/dakasa/dakasa-tartaro-fe/deploy/base/service.yaml
cat /Users/dakasa/projects/dakasa/dakasa-tartaro-fe/deploy/base/deployment.yaml
cat /Users/dakasa/projects/dakasa/dakasa-tartaro-fe/deploy/base/kustomization.yaml
```

- [ ] **Step 3: Find the existing ForwardAuth Middleware (used by surface-console for SSO)**

```bash
find /Users/dakasa/projects -name "*.yaml" -exec grep -l "ForwardAuth\|surface-auth" {} \; 2>/dev/null | head -5
```

Note the existing Middleware name and namespace — surface deploys will REFERENCE it, not create a duplicate.

- [ ] **Step 4: Commit inspection notes (optional)**

```bash
cd /Users/dakasa/projects/yggdrasil/surface-template
cat > deploy/SURFACE_DEPLOY_NOTES.md <<'EOF'
# Surface deploy pattern (Phase 0d)

Reference repo for layout: dakasa-tartaro-fe (deploy/base + deploy/overlays/validation).

Each integration surface follows the same shape:

```
integration-<name>/
└── deploy/surface-base/
    ├── deployment.yaml      # nginx + SPA bundle, replicas: 1
    ├── service.yaml         # ClusterIP, port 80
    ├── ingress.yaml         # path-based, /s/<name>, middleware: strip + auth
    └── kustomization.yaml
```

The strip-surface-prefix Middleware is shared across all surfaces and lives in surface-template/deploy/middleware-strip-surface-prefix.yaml. It is applied once cluster-wide.

ForwardAuth uses the existing surface-auth Middleware (referenced by name in ingress annotations).
EOF
git add deploy/SURFACE_DEPLOY_NOTES.md
git commit -m "docs(deploy): surface deploy pattern notes"
```

---

## Task 2: Shared strip-surface-prefix Middleware

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/surface-template/deploy/middleware-strip-surface-prefix.yaml`

- [ ] **Step 1: Write the Middleware manifest**

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: strip-surface-prefix
  namespace: dakasa
spec:
  stripPrefixRegex:
    regex:
      - "^/s/[^/]+"
```

This strips exactly the `/s/<name>` portion (one path segment after `/s/`) leaving the rest of the URL intact. So `/s/slack/instance/abc/overview` → `/instance/abc/overview` reaches nginx, which serves `index.html` via SPA fallback in nginx.conf.

- [ ] **Step 2: Dry-run validate**

```bash
kubectl apply --dry-run=client -f deploy/middleware-strip-surface-prefix.yaml
```

Expected: `middleware.traefik.io/strip-surface-prefix created (dry run)`.

- [ ] **Step 3: Apply via Yggdrasil workflow**

Per memory `feedback_yggdrasil_only`: mutations go through Yggdrasil. Create a one-off workflow run that applies this manifest via integration-kubernetes:

```bash
# Pull workflow token from cluster secret
TOKEN=$(kubectl get secret yggdrasil-secrets -n dakasa -o jsonpath='{.data.YGGDRASIL_WORKFLOW_RUN_TOKEN}' | base64 -d)

curl -X POST "https://yggdrasil.dakasa.me/api/v1/workflow-runs" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "workflow_name": "apply-middleware-strip-surface-prefix",
    "input": {
      "manifest_path": "surface-template/deploy/middleware-strip-surface-prefix.yaml"
    }
  }'
```

(If a generic "apply-yaml" workflow does not exist yet, fall back to: pull the manifest content into the workflow body and let integration-kubernetes apply it via Apply capability.)

- [ ] **Step 4: Verify**

```bash
kubectl get middleware.traefik.io/strip-surface-prefix -n dakasa -o yaml
```

Expected: the resource exists with the spec above.

- [ ] **Step 5: Commit**

```bash
cd /Users/dakasa/projects/yggdrasil/surface-template
git add deploy/middleware-strip-surface-prefix.yaml
git commit -m "feat(deploy): shared Traefik Middleware strip-surface-prefix"
```

---

## Task 3: Canonical surface deploy template (in surface-template repo)

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/surface-template/deploy/surface-base/deployment.yaml`
- Create: `/Users/dakasa/projects/yggdrasil/surface-template/deploy/surface-base/service.yaml`
- Create: `/Users/dakasa/projects/yggdrasil/surface-template/deploy/surface-base/ingress.yaml`
- Create: `/Users/dakasa/projects/yggdrasil/surface-template/deploy/surface-base/kustomization.yaml`
- Create: `/Users/dakasa/projects/yggdrasil/surface-template/deploy/surface-base/README.md`

- [ ] **Step 1: Write deployment.yaml**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: SURFACE_NAME                              # replaced by overlay (e.g., surface-slack)
  namespace: dakasa
  labels:
    app.kubernetes.io/name: SURFACE_NAME
    app.kubernetes.io/component: surface
    app.kubernetes.io/part-of: yggdrasil
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: SURFACE_NAME
  template:
    metadata:
      labels:
        app.kubernetes.io/name: SURFACE_NAME
        app.kubernetes.io/component: surface
    spec:
      imagePullSecrets:
        - name: ecr-pull-sa-east-1                # for private adapters using ECR; harmless if not needed
      containers:
        - name: nginx
          image: SURFACE_IMAGE:SURFACE_TAG        # replaced by overlay
          ports:
            - containerPort: 80
          readinessProbe:
            httpGet:
              path: /healthz
              port: 80
            initialDelaySeconds: 2
            periodSeconds: 5
          livenessProbe:
            httpGet:
              path: /healthz
              port: 80
            initialDelaySeconds: 10
            periodSeconds: 15
          resources:
            requests: { cpu: "10m", memory: "32Mi" }
            limits:   { cpu: "100m", memory: "128Mi" }
```

- [ ] **Step 2: Write service.yaml**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: SURFACE_NAME
  namespace: dakasa
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: SURFACE_NAME
  ports:
    - name: http
      port: 80
      targetPort: 80
```

- [ ] **Step 3: Write ingress.yaml**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: SURFACE_NAME
  namespace: dakasa
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    traefik.ingress.kubernetes.io/router.middlewares: dakasa-strip-surface-prefix@kubernetescrd,dakasa-surface-auth@kubernetescrd
spec:
  ingressClassName: traefik
  tls:
    - hosts:
        - yggdrasil.dakasa.me
      secretName: yggdrasil-dakasa-me-tls
  rules:
    - host: yggdrasil.dakasa.me
      http:
        paths:
          - path: /s/SURFACE_PATH_SUFFIX         # replaced by overlay (e.g., /s/slack)
            pathType: Prefix
            backend:
              service:
                name: SURFACE_NAME
                port:
                  number: 80
```

NOTE on `surface-auth` middleware: that ForwardAuth middleware is the one currently fronting `surface-console`. If the actual name in the cluster differs (`yggdrasil-auth`, `dakasa-auth`, etc.), update the annotation accordingly during Task 4 smoke test.

- [ ] **Step 4: Write kustomization.yaml**

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: dakasa

labels:
  - pairs:
      app.kubernetes.io/component: surface
      app.kubernetes.io/part-of: yggdrasil
    includeSelectors: false

resources:
  - deployment.yaml
  - service.yaml
  - ingress.yaml
```

- [ ] **Step 5: Write README.md**

```markdown
# Surface deploy base

Canonical kustomize base for an Yggdrasil integration surface. Each
`integration-<name>` repo COPIES this directory into its own
`deploy/surface-base/` and patches via `deploy/surface-overlays/<env>/`.

## Substitutions

`SURFACE_NAME` → e.g., `surface-slack`
`SURFACE_IMAGE` → full image ref (ECR or GHCR)
`SURFACE_TAG` → image tag (git SHA)
`SURFACE_PATH_SUFFIX` → URL suffix; for `surface-slack` use `slack`

## Overlay example

`deploy/surface-overlays/validation/kustomization.yaml`:

\`\`\`yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: dakasa
resources:
  - ../../surface-base
patches:
  - target: { kind: Deployment, name: SURFACE_NAME }
    patch: |-
      - op: replace
        path: /metadata/name
        value: surface-slack
      - op: replace
        path: /spec/template/spec/containers/0/image
        value: 153828470928.dkr.ecr.us-east-1.amazonaws.com/ghcr/dakasa-yggdrasil/surface-slack:abc123
      ...
\`\`\`

Or use `kustomize edit set image` in CI.

## Cluster prerequisites

- Traefik Middleware `dakasa/strip-surface-prefix` (applied via Task 2)
- ForwardAuth middleware (e.g. `dakasa/surface-auth`) — already present
- `ecr-pull-sa-east-1` imagePullSecret in `dakasa` namespace (for private surfaces)
- Wildcard cert `yggdrasil-dakasa-me-tls` for `yggdrasil.dakasa.me` (already present)
```

- [ ] **Step 6: Dry-run validate the base manifests**

```bash
cd /Users/dakasa/projects/yggdrasil/surface-template
kubectl apply --dry-run=client -k deploy/surface-base/
```

Expected: success (kustomize renders + k8s validates the templated names; the placeholder strings are syntactically valid k8s identifiers).

- [ ] **Step 7: Commit**

```bash
git add deploy/surface-base
git commit -m "feat(deploy): canonical surface kustomize base + overlay docs"
```

---

## Task 4: Placeholder surface (end-to-end smoke)

**Files:**
- Create directory: `/Users/dakasa/projects/yggdrasil/surface-template/deploy/surface-overlays/placeholder/kustomization.yaml`

The placeholder uses a public nginx image (no surface SPA needed) to validate the full request path: DNS → Traefik → Middleware (strip + auth) → Service → nginx.

- [ ] **Step 1: Write placeholder overlay**

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: dakasa
resources:
  - ../../surface-base
patches:
  - target:
      kind: Deployment
      name: SURFACE_NAME
    patch: |-
      - op: replace
        path: /metadata/name
        value: surface-placeholder
      - op: replace
        path: /metadata/labels/app.kubernetes.io~1name
        value: surface-placeholder
      - op: replace
        path: /spec/selector/matchLabels/app.kubernetes.io~1name
        value: surface-placeholder
      - op: replace
        path: /spec/template/metadata/labels/app.kubernetes.io~1name
        value: surface-placeholder
      - op: replace
        path: /spec/template/spec/containers/0/image
        value: nginxdemos/hello:plain-text
      - op: remove
        path: /spec/template/spec/containers/0/readinessProbe
      - op: remove
        path: /spec/template/spec/containers/0/livenessProbe
  - target:
      kind: Service
      name: SURFACE_NAME
    patch: |-
      - op: replace
        path: /metadata/name
        value: surface-placeholder
      - op: replace
        path: /spec/selector/app.kubernetes.io~1name
        value: surface-placeholder
  - target:
      kind: Ingress
      name: SURFACE_NAME
    patch: |-
      - op: replace
        path: /metadata/name
        value: surface-placeholder
      - op: replace
        path: /spec/rules/0/http/paths/0/path
        value: /s/placeholder
      - op: replace
        path: /spec/rules/0/http/paths/0/backend/service/name
        value: surface-placeholder
```

- [ ] **Step 2: Apply via Yggdrasil workflow**

```bash
TOKEN=$(kubectl get secret yggdrasil-secrets -n dakasa -o jsonpath='{.data.YGGDRASIL_WORKFLOW_RUN_TOKEN}' | base64 -d)
curl -X POST "https://yggdrasil.dakasa.me/api/v1/workflow-runs" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "workflow_name": "apply-kustomize",
    "input": {
      "repo": "dakasa-yggdrasil/surface-template",
      "path": "deploy/surface-overlays/placeholder",
      "ref": "main"
    }
  }'
```

(If `apply-kustomize` workflow doesn't exist with this exact shape, adapt to whatever integration-kubernetes workflow is available, or invoke `kubectl apply -k` via integration-yggdrasil-self workflow.)

- [ ] **Step 3: Verify the placeholder is reachable**

```bash
# Wait a moment for pod startup
kubectl rollout status deployment/surface-placeholder -n dakasa --timeout=60s

# From a shell with cluster network access:
curl -sk https://yggdrasil.dakasa.me/s/placeholder/ -H "Cookie: <valid-session-cookie>" -o /dev/null -w "%{http_code}\n"
```

Expected: `200` (nginx default page). If `401`/`403`: ForwardAuth middleware name in ingress.yaml is wrong — fix and re-apply. If `404`: Middleware not applied or StripPrefix regex wrong.

- [ ] **Step 4: Verify path stripping**

```bash
# Hitting nginx directly via service (bypass ingress) to confirm nginx is alive:
kubectl exec -it deploy/surface-placeholder -n dakasa -- curl -s http://localhost/
```

Compare to what the ingress returns. Both should serve the same content if strip-prefix works correctly.

- [ ] **Step 5: Commit overlay**

```bash
cd /Users/dakasa/projects/yggdrasil/surface-template
git add deploy/surface-overlays/placeholder
git commit -m "feat(deploy): placeholder surface overlay (E2E smoke)"
```

---

## Task 5: Cleanup placeholder (after smoke passes)

**Files:** none (delete only)

- [ ] **Step 1: Delete placeholder resources via Yggdrasil workflow**

```bash
TOKEN=$(kubectl get secret yggdrasil-secrets -n dakasa -o jsonpath='{.data.YGGDRASIL_WORKFLOW_RUN_TOKEN}' | base64 -d)
curl -X POST "https://yggdrasil.dakasa.me/api/v1/workflow-runs" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "workflow_name": "delete-kustomize",
    "input": {
      "repo": "dakasa-yggdrasil/surface-template",
      "path": "deploy/surface-overlays/placeholder",
      "ref": "main"
    }
  }'
```

- [ ] **Step 2: Verify deletion**

```bash
kubectl get deploy,svc,ingress -n dakasa -l app.kubernetes.io/name=surface-placeholder
```

Expected: `No resources found`.

- [ ] **Step 3: Keep the overlay in repo (for re-running smoke later)**

The overlay yaml stays — it's useful for re-running smoke tests when deploy pipelines change. Just delete the cluster-side resources.

- [ ] **Step 4: Tag sync gate**

```bash
cd /Users/dakasa/projects/yggdrasil/surface-template
git commit --allow-empty -m "chore: Phase 0d complete — surface deploy template + middleware live"
```

---

## Phase 0d sync gate (after Task 5)

Before Phase 1 surfaces deploy:

1. ✅ Traefik Middleware `dakasa/strip-surface-prefix` applied
2. ✅ `surface-template/deploy/surface-base/` checked in with deployment + service + ingress + kustomization
3. ✅ Placeholder surface smoke proved the end-to-end path works (deploy + ingress + auth + strip → nginx)
4. ✅ Placeholder deleted (cluster-side) but overlay yaml retained for future smoke runs
5. ✅ README.md documents the substitution pattern for Phase 1 surfaces

---

## Final code reviewer dispatch (after Task 5)

After all tasks complete, dispatch one final code reviewer. Reviewer checks:

- `strip-surface-prefix` regex strips exactly one path segment after `/s/` (and verified via the placeholder smoke)
- Ingress references both middlewares in correct order (`strip-surface-prefix` BEFORE `surface-auth`; auth runs against the stripped path which is what the SPA expects)
- Deployment uses `replicas: 1` per spec §7.5 (V1 conservative)
- Health probes hit `/healthz` (matches surface-toolkit's nginx.conf which exposes /healthz)
- ImagePullSecret `ecr-pull-sa-east-1` is harmless for public-image surfaces (cluster ignores when not needed)
- Resource limits are tight enough for SPA serving (10m CPU req / 100m limit; 32Mi req / 128Mi limit)
- No hardcoded references to specific integrations — base is fully templated via SURFACE_NAME / SURFACE_IMAGE / SURFACE_TAG / SURFACE_PATH_SUFFIX
- README documents how Phase 1 will use overlays

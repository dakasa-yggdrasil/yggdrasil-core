"""Generate brand-identifying SVGs for Yggdrasil integration_type manifests.

Each SVG is a 24x24 vector with the brand's primary color and a
recognizable mark (not the trademark logo — geometric stand-ins that
read as the brand). PATCH'd into the manifest as spec.icon.url so the
console renders them directly (no /brand/ hardcoding).
"""

import json
import urllib.request
import urllib.parse
import urllib.error
import sys
import os

YGG_URL = "https://yggdrasil.dakasa.me"
TOKEN = "ys_xCblmjUvQSjkhlApq3GVYgkH8_0CVp_BAlFxMmOWUN4"


def svg_data_uri(svg: str) -> str:
    return "data:image/svg+xml;utf8," + urllib.parse.quote(svg)


# Each SVG is keyed by integration_type name.
# Where possible the marks use brand-signature shapes/colors:
#   - Stripe: characteristic flowing S
#   - PostgreSQL: simplified elephant head
#   - Kubernetes: 7-segment helm wheel
#   - RabbitMQ: rabbit ears + dot
#   - Heimdall: viking shield
#   - Tartaro: trident (Hades/underworld)
#   - Yggdrasil: world tree silhouette
#   - Loki: yellow flame (logs)
#   - NfeIO: brazilian invoice "NF" stamp
ICONS = {
    "stripe": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#635BFF"/><path fill="#fff" d="M13.5 9.3c-1.4-.5-2.2-.9-2.2-1.6 0-.6.5-.9 1.3-.9 1.5 0 3 .6 4.1 1.1l.6-3.7c-.9-.4-2.6-1-4.9-1-1.7 0-3.1.4-4.1 1.2C7.2 5.3 6.7 6.6 6.7 8c0 2.7 1.7 3.9 4.4 4.9 1.7.6 2.3 1 2.3 1.7 0 .7-.6 1-1.6 1-1.3 0-3.3-.6-4.7-1.4l-.6 3.7c1.2.7 3.4 1.4 5.7 1.4 1.8 0 3.3-.4 4.3-1.2 1.1-.9 1.7-2.2 1.7-3.9 0-2.8-1.7-3.9-4.5-4.9z"/></svg>',

    "github": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#1a1e25"/><path fill="#fff" d="M12 4.8c-3.97 0-7.2 3.23-7.2 7.2 0 3.18 2.06 5.88 4.92 6.83.36.07.49-.15.49-.34v-1.22c-2 .43-2.42-.96-2.42-.96-.33-.83-.8-1.05-.8-1.05-.65-.45.05-.44.05-.44.72.05 1.1.74 1.1.74.64 1.1 1.68.78 2.09.6.07-.46.25-.78.45-.96-1.6-.18-3.28-.8-3.28-3.56 0-.78.28-1.43.74-1.93-.07-.18-.32-.92.07-1.9 0 0 .6-.2 1.98.74.57-.16 1.19-.24 1.8-.24.61 0 1.23.08 1.8.24 1.37-.94 1.98-.74 1.98-.74.39.98.14 1.72.07 1.9.46.5.74 1.15.74 1.93 0 2.77-1.68 3.38-3.28 3.55.26.22.48.66.48 1.32v1.96c0 .19.13.41.5.34 2.85-.95 4.92-3.65 4.92-6.83 0-3.97-3.23-7.2-7.2-7.2z"/></svg>',

    "slack": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#fff"/><path fill="#E01E5A" d="M7.5 14.5c0 1.1-.9 2-2 2s-2-.9-2-2 .9-2 2-2h2v2zm1 0c0-1.1.9-2 2-2s2 .9 2 2v5c0 1.1-.9 2-2 2s-2-.9-2-2v-5z"/><path fill="#36C5F0" d="M10.5 6.5c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2v2h-2zm0 1c1.1 0 2 .9 2 2s-.9 2-2 2h-5c-1.1 0-2-.9-2-2s.9-2 2-2h5z"/><path fill="#2EB67D" d="M17.5 9.5c0-1.1.9-2 2-2s2 .9 2 2-.9 2-2 2h-2v-2zm-1 0c0 1.1-.9 2-2 2s-2-.9-2-2v-5c0-1.1.9-2 2-2s2 .9 2 2v5z"/><path fill="#ECB22E" d="M14.5 17.5c1.1 0 2 .9 2 2s-.9 2-2 2-2-.9-2-2v-2h2zm0-1c-1.1 0-2-.9-2-2s.9-2 2-2h5c1.1 0 2 .9 2 2s-.9 2-2 2h-5z"/></svg>',

    "aws": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#232F3E"/><path fill="#FF9900" d="M6.5 13.6c0 .3 0 .5.1.7 0 .2.1.4.2.6 0 .1.1.1.1.2s0 .1-.1.1l-.5.3-.1.1c-.1 0-.1 0-.2-.1-.1-.1-.2-.2-.2-.3-.1-.1-.1-.3-.2-.4-.6.7-1.3 1-2.2 1-.6 0-1.1-.2-1.5-.5-.4-.4-.6-.8-.6-1.4 0-.6.2-1.1.7-1.5.4-.4 1-.6 1.8-.6.2 0 .5 0 .8.1.2 0 .5.1.8.2v-.5c0-.5-.1-.9-.3-1.1-.2-.2-.6-.3-1.1-.3-.2 0-.5 0-.7.1-.3 0-.5.1-.7.2-.1 0-.2.1-.3.1h-.1c-.1 0-.1-.1-.1-.2v-.4c0-.1 0-.1.1-.2.1 0 .1-.1.2-.1.2-.1.5-.2.8-.3.3-.1.7-.1 1-.1.8 0 1.4.2 1.7.5.4.4.5.9.5 1.7v2.3zm-3 1.2c.2 0 .5 0 .7-.1.3-.1.5-.2.7-.4.1-.1.2-.2.2-.4 0-.1.1-.3.1-.5v-.3c-.2 0-.4-.1-.6-.1h-.6c-.4 0-.8.1-1 .3-.2.2-.3.4-.3.7 0 .3.1.5.3.6.1.1.3.2.5.2zm5.9.8c-.1 0-.2 0-.2-.1-.1 0-.1-.1-.1-.3l-1.7-5.7c-.1-.1-.1-.2-.1-.3s0-.1.1-.1h.7c.1 0 .2 0 .2.1.1.1.1.1.1.3l1.2 4.7 1.1-4.7c0-.1.1-.2.1-.3.1 0 .2-.1.3-.1h.5c.1 0 .2 0 .3.1.1.1.1.1.1.3l1.1 4.7 1.2-4.7c0-.1.1-.2.1-.3.1-.1.1-.1.2-.1h.6c.1 0 .2 0 .2.1v.2c0 .1 0 .2-.1.3L13.9 15c0 .1-.1.2-.1.3-.1.1-.2.1-.3.1h-.5c-.1 0-.2 0-.3-.1-.1-.1-.1-.1-.1-.3l-1.1-4.6-1.1 4.5c0 .1-.1.2-.1.3-.1.1-.2.1-.3.1h-.6zm9.4.2c-.3 0-.7 0-1-.1-.3-.1-.6-.2-.8-.3-.1-.1-.2-.1-.2-.2v-.4c0-.2.1-.2.2-.2h.1c.1 0 .1.1.2.1.3.1.6.2.8.3.3.1.5.1.8.1.4 0 .7-.1.9-.2.2-.1.3-.3.3-.6 0-.2-.1-.3-.2-.4-.1-.1-.4-.2-.7-.3l-1-.3c-.5-.2-.9-.4-1.2-.7-.2-.3-.4-.7-.4-1.1 0-.3.1-.6.2-.8.1-.2.3-.4.5-.6.2-.2.5-.3.7-.4.3-.1.6-.1.9-.1.2 0 .3 0 .5.1.1 0 .3.1.4.1.1 0 .2.1.4.1.1 0 .2.1.2.1.1.1.1.1.1.2v.4c0 .2-.1.3-.2.3-.1 0-.2 0-.4-.1-.4-.2-.9-.3-1.4-.3-.4 0-.7.1-.8.2-.2.1-.3.3-.3.6 0 .2.1.3.2.4.1.1.4.2.8.4l1 .3c.5.2.8.4 1 .7.2.3.3.6.3 1 0 .3-.1.6-.2.9-.1.3-.3.5-.5.7-.2.2-.5.3-.8.4-.3 0-.6.1-.9.1zm-.4 2.3c-.3.2-.6.4-.9.5-.4.1-.7.2-1.1.3l.5-1c.1 0 .2-.1.3-.1.3-.1.5-.3.5-.5.1-.2.1-.4 0-.6 0-.1-.1-.2-.1-.4-.1-.1-.1-.2-.2-.4 0-.1-.1-.2-.1-.3 0-.1 0-.1.1-.2.1 0 .1-.1.2-.1.2 0 .4.1.6.2.2.1.4.3.5.5.1.2.2.4.3.7.1.3.1.5.1.8 0 .3 0 .5-.1.7-.1.2-.1.4-.1.5z"/></svg>',

    "grafana": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#1f0044"/><circle cx="12" cy="12" r="6" fill="none" stroke="#F46800" stroke-width="2"/><path fill="#F46800" d="M12 5.5l1.5 3-3 0z"/><circle cx="12" cy="12" r="2" fill="#F46800"/></svg>',

    "kubernetes": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#326CE5"/><path fill="#fff" d="M12 4l-6 3v6l6 3 6-3V7l-6-3zm0 1.5l4.5 2.25-4.5 2.25-4.5-2.25L12 5.5zm-5 4l4 2v4l-4-2v-4zm10 0v4l-4 2v-4l4-2z"/></svg>',

    "postgres": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#336791"/><ellipse cx="12" cy="8" rx="6" ry="2" fill="#fff"/><path fill="#fff" d="M6 8v4c0 1.1 2.7 2 6 2s6-.9 6-2V8c0 1.1-2.7 2-6 2s-6-.9-6-2zm0 4v4c0 1.1 2.7 2 6 2s6-.9 6-2v-4c0 1.1-2.7 2-6 2s-6-.9-6-2z"/></svg>',

    "database-admin-postgres": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#336791"/><ellipse cx="12" cy="8" rx="6" ry="2" fill="#fff"/><path fill="#fff" d="M6 8v4c0 1.1 2.7 2 6 2s6-.9 6-2V8c0 1.1-2.7 2-6 2s-6-.9-6-2zm0 4v4c0 1.1 2.7 2 6 2s6-.9 6-2v-4c0 1.1-2.7 2-6 2s-6-.9-6-2z"/></svg>',

    "schema-migrations-goose-postgres": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#0d8163"/><path fill="#fff" d="M6 7l3-2 3 2v2l3-2 3 2v2l-3 2v-2l-3 2v2l3-2v2l-3 2-3-2v-2L6 13v-2l3-2V7l-3 2V7z"/></svg>',

    "rabbitmq": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#ff6600"/><path fill="#fff" d="M18 11h-4V6h-2v5H9V6H7v7h7v5h4v-7z"/></svg>',

    "rabbitmq-kubernetes": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#ff6600"/><path fill="#fff" d="M18 11h-4V6h-2v5H9V6H7v7h7v5h4v-7z"/></svg>',

    "rabbitmq-topology": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#ff6600"/><path fill="#fff" d="M18 11h-4V6h-2v5H9V6H7v7h7v5h4v-7z"/></svg>',

    "heimdall": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#1f6b5e"/><path fill="#fff" d="M12 4l-5 2v6c0 3.5 2.5 6.5 5 7 2.5-.5 5-3.5 5-7V6l-5-2zm0 2.5L15.5 8v3.5c0 2.5-1.5 4.5-3.5 5-2-.5-3.5-2.5-3.5-5V8L12 6.5z"/><circle cx="12" cy="11" r="1.5" fill="#1f6b5e"/></svg>',

    "tartaro": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#c89858"/><path fill="#fff" d="M8 5v5l-2 2h2v8h2V12h4v8h2V12h2l-2-2V5l-2 2v3h-4V7l-2-2z"/></svg>',

    "yggdrasil-self": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#7f5af0"/><path fill="#fff" d="M12 4c1 0 2.5 1 3 2.5L13 8l1 2-2.5 1.5L12 14h-1l1-2L9 8l-1 2-2.5-1.5L7 6.5C7.5 5 9 4 10 4l1 1 1-1zm-1 11h2v4h-2v-4z"/></svg>',

    "nfeio": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#1da1f2"/><path fill="#fff" d="M5 5h4l3 7V5h2l3 7V5h2v14h-2l-3-7v7h-2l-3-7v7H5V5z"/></svg>',

    "efi": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#e8550b"/><path fill="#fff" d="M7 5h7v3h-4v2.5h3.5v3H10V16h4v3H7V5z"/><path fill="#fff" d="M16 5h2v14h-2z"/></svg>',

    "loki": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#fff"/><path fill="#FCC02D" d="M12 3c-1 2 1 3 0 5-1 1.5-3 1-3 4 0 3 2 5 5 5s5-2 5-5c0-2.5-2-3-2-5 0-1.5 0-2.5-1-3-1 1 0 2 0 3-2 0-2-2-2-3-1 0-1.5.5-2 1-.5-1-1-1.5 0-2z"/></svg>',

    "prometheus": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#fff"/><path fill="#E6522C" d="M12 3c-1 1 0 2-1 4-1 1.5-3 2-3 5 0 3 3 5 5 5s5-2 5-5c0-3-2-3.5-3-5-1-2 0-3-1-4-.5 1.5-1 1.5-1 3 0 1.5-1 2-2 2s-2-.5-2-2c0-1.5-.5-1.5-1-3z"/><rect x="9" y="15" width="6" height="2" fill="#E6522C"/></svg>',

    "google-workspace": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#fff"/><path fill="#4285F4" d="M19 12c0-.6-.05-1.15-.15-1.7H12v3.25h3.95c-.18.9-.7 1.65-1.45 2.15v1.8h2.35c1.4-1.3 2.15-3.2 2.15-5.5z"/><path fill="#34A853" d="M12 19.5c2 0 3.65-.65 4.85-1.8l-2.35-1.8c-.65.45-1.5.7-2.5.7-1.95 0-3.55-1.3-4.15-3.1H5.45v1.85C6.65 17.85 9.15 19.5 12 19.5z"/><path fill="#FBBC04" d="M7.85 13.5c-.15-.45-.25-.95-.25-1.5s.1-1.05.25-1.5V8.65H5.45c-.5 1-.8 2.15-.8 3.35s.3 2.35.8 3.35l2.4-1.85z"/><path fill="#EA4335" d="M12 7.4c1.1 0 2.1.4 2.85 1.1l2.05-2.05C15.65 5.2 14 4.5 12 4.5c-2.85 0-5.35 1.65-6.55 4.15l2.4 1.85c.6-1.8 2.2-3.1 4.15-3.1z"/></svg>',

    "gcp": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#fff"/><path fill="#4285F4" d="M12 4l4 7h-8z"/><path fill="#34A853" d="M16 11l4 7H8z"/><path fill="#EA4335" d="M8 11l-4 7h8z"/><path fill="#FBBC04" d="M12 18l-2-3.5h4z"/></svg>',

    "kustomize": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#326CE5"/><path fill="#fff" d="M5 6h14v3H5zm0 4.5h14v3H5zm0 4.5h14v3H5z"/><circle cx="7" cy="7.5" r="1" fill="#326CE5"/><circle cx="7" cy="12" r="1" fill="#326CE5"/><circle cx="7" cy="16.5" r="1" fill="#326CE5"/></svg>',

    "manifest-sources-kustomize": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#326CE5"/><path fill="#fff" d="M5 6h14v3H5zm0 4.5h14v3H5zm0 4.5h14v3H5z"/><circle cx="7" cy="7.5" r="1" fill="#326CE5"/><circle cx="7" cy="12" r="1" fill="#326CE5"/><circle cx="7" cy="16.5" r="1" fill="#326CE5"/></svg>',

    "secrets-management-aws-secrets-manager": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#232F3E"/><path fill="#FF9900" d="M12 4a4 4 0 00-4 4v2H6v9h12v-9h-2V8a4 4 0 00-4-4zm0 2a2 2 0 012 2v2h-4V8a2 2 0 012-2z"/></svg>',

    "secrets-management-gcp-secret-manager": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#1a73e8"/><path fill="#fff" d="M12 4a4 4 0 00-4 4v2H6v9h12v-9h-2V8a4 4 0 00-4-4zm0 2a2 2 0 012 2v2h-4V8a2 2 0 012-2z"/></svg>',

    "ai-runtime": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#6e56cf"/><circle cx="12" cy="12" r="6" fill="none" stroke="#fff" stroke-width="1.5"/><circle cx="9.5" cy="10.5" r="1" fill="#fff"/><circle cx="14.5" cy="10.5" r="1" fill="#fff"/><path fill="none" stroke="#fff" stroke-width="1.5" stroke-linecap="round" d="M9 14.5c1 1 2 1.5 3 1.5s2-.5 3-1.5"/></svg>',

    "grafana-kubernetes": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect width="24" height="24" rx="5" fill="#326CE5"/><path fill="#fff" d="M12 4l-6 3v6l6 3 6-3V7l-6-3zm0 1.5l4.5 2.25-4.5 2.25-4.5-2.25L12 5.5zm-5 4l4 2v4l-4-2v-4zm10 0v4l-4 2v-4l4-2z"/><circle cx="12" cy="11" r="2" fill="#F46800"/></svg>',
}


def patch_icon(name: str, svg: str) -> dict:
    url = svg_data_uri(svg)
    # Patch /api/v1/manifests by POSTing the same name/namespace with updated spec
    # First fetch current manifest
    req = urllib.request.Request(
        f"{YGG_URL}/api/v1/manifests?kind=integration_type&name={name}",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"name": name, "status": "fetch-failed", "error": str(e)}
    manifests = data.get("manifests", [])
    if not manifests:
        return {"name": name, "status": "not-found"}
    current = manifests[0]
    spec = current.get("spec", {})
    spec["icon"] = {"url": url, "accent": spec.get("icon", {}).get("accent", ""), "aria_label": name}
    # POST
    body = {
        "namespace": current["metadata"]["namespace"],
        "name": current["metadata"]["name"],
        "spec": spec,
    }
    post = urllib.request.Request(
        f"{YGG_URL}/api/v1/manifests?kind=integration_type",
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(post, timeout=30) as resp:
            return {"name": name, "status": "ok", "code": resp.status}
    except urllib.error.HTTPError as e:
        return {"name": name, "status": "post-failed", "code": e.code, "body": e.read().decode()[:200]}


def main():
    results = []
    for name, svg in ICONS.items():
        r = patch_icon(name, svg)
        results.append(r)
        print(json.dumps(r), file=sys.stderr)
    success = [r for r in results if r["status"] == "ok"]
    failed = [r for r in results if r["status"] != "ok"]
    print(f"\nOK: {len(success)}/{len(results)}", file=sys.stderr)
    if failed:
        print(f"FAILED:", file=sys.stderr)
        for f in failed:
            print(f"  {f}", file=sys.stderr)


if __name__ == "__main__":
    main()

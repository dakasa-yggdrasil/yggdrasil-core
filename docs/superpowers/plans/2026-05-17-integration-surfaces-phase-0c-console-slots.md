# Integration Surfaces — Phase 0c: surface-console IntegrationSurfaceSlot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add IntegrationSurfaceSlot/IntegrationSurfaceCard rendering machinery to `surface-console`, with consumption in `/`, `/ops/integrations`, and `/colaboradores/:id`. After this phase, console renders empty slot states (until Phase 1 ships actual surfaces, then cards populate dynamically).

**Architecture:** New module `src/lib/integration-surfaces/` with `types.ts`, `useIntegrationSurfaces.ts`, `useIntegrationSurfacesByMany.ts`, `IntegrationSurfaceCard.tsx`, `IntegrationSurfaceSlot.tsx`. Three existing pages refactored to embed `<IntegrationSurfaceSlot>`. No changes to backend (Phase 0b owns that contract); console only consumes `GET /api/v1/integration-surfaces`.

**Tech Stack:** React 19 + TypeScript + Vite + @tanstack/react-query + @mui/material + react-router-dom 7 (existing in surface-console).

**Spec reference:** `/Users/dakasa/projects/yggdrasil/yggdrasil-core/docs/superpowers/specs/2026-05-17-integration-surfaces-design.md` §5.

**Working directory:** `/Users/dakasa/projects/yggdrasil/surface-console/`.

**Commit cadence:** push direct to `main`. No co-author trailers.

---

## Task 1: Module bootstrap

**Files:**
- Create: `src/lib/integration-surfaces/types.ts`
- Create: `src/lib/integration-surfaces/index.ts` (empty re-export entry)
- Create: `src/lib/integration-surfaces/types.test.ts`

- [ ] **Step 1: Write failing test**

`src/lib/integration-surfaces/types.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import type { IntegrationSurfaceManifestT, SlotID } from "./types";
import { isSlotID } from "./types";

describe("IntegrationSurfaceManifestT", () => {
  it("type-checks a minimal manifest", () => {
    const m: IntegrationSurfaceManifestT = {
      id: "uuid",
      name: "surface-slack",
      integration_type: "slack",
      category: "integration",
      spec: {
        category: "integration",
        runtime: { kind: "spa", base_path: "/s/slack" },
        display: { title: "Slack", appears_on: ["ops-integrations"] },
        core_contracts: []
      },
      active: true,
      registered_at: "2026-05-17T00:00:00Z",
      updated_at: "2026-05-17T00:00:00Z"
    };
    expect(m.name).toBe("surface-slack");
  });
});

describe("isSlotID", () => {
  it("recognises known slot IDs", () => {
    const knownSlots: SlotID[] = [
      "console-home",
      "ops-integrations",
      "me",
      "equipe",
      "orgchart",
      "colaborador-detail"
    ];
    knownSlots.forEach((s) => expect(isSlotID(s)).toBe(true));
  });

  it("rejects unknown strings", () => {
    expect(isSlotID("random")).toBe(false);
  });
});
```

- [ ] **Step 2: Run — expect FAIL**

Run: `npm test -- src/lib/integration-surfaces/types.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement types.ts**

```ts
export type SlotID =
  | "console-home"
  | "ops-integrations"
  | "me"
  | "equipe"
  | "orgchart"
  | "colaborador-detail";

const KNOWN_SLOTS: SlotID[] = [
  "console-home",
  "ops-integrations",
  "me",
  "equipe",
  "orgchart",
  "colaborador-detail"
];

export function isSlotID(s: string): s is SlotID {
  return (KNOWN_SLOTS as readonly string[]).includes(s);
}

export interface SurfaceRuntimeT {
  kind: "spa" | "http_api";
  exposure?: string;
  base_path: string;
  health_path?: string;
  image?: string;
}

export interface SurfaceDisplayT {
  title: string;
  subtitle?: string;
  icon?: string;
  color_token?: string;
  appears_on?: SlotID[];
}

export interface SurfaceSpecT {
  category: "integration" | "core" | "domain";
  owners?: string[];
  runtime: SurfaceRuntimeT;
  display: SurfaceDisplayT;
  core_contracts?: string[];
  capabilities?: Array<{ name: string; tabs?: string[] }>;
}

export interface IntegrationSurfaceManifestT {
  id: string;
  name: string;
  integration_type: string | null;
  category: "integration" | "core" | "domain";
  spec: SurfaceSpecT;
  active: boolean;
  registered_at: string;
  updated_at: string;
}

export interface IntegrationSurfacesListResponse {
  items: IntegrationSurfaceManifestT[];
  total: number;
}
```

- [ ] **Step 4: Implement index.ts (empty for now)**

```ts
export * from "./types";
```

- [ ] **Step 5: Run — expect PASS**

Run: `npm test -- src/lib/integration-surfaces/types.test.ts`
Expected: PASS — 3 tests.

- [ ] **Step 6: Commit**

```bash
git add src/lib/integration-surfaces
git commit -m "feat(surfaces): types module — IntegrationSurfaceManifestT, SlotID, isSlotID"
```

---

## Task 2: useIntegrationSurfaces hook

**Files:**
- Create: `src/lib/integration-surfaces/useIntegrationSurfaces.ts`
- Create: `src/lib/integration-surfaces/useIntegrationSurfaces.test.tsx`

- [ ] **Step 1: Write failing test**

`src/lib/integration-surfaces/useIntegrationSurfaces.test.tsx`:

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useIntegrationSurfaces } from "./useIntegrationSurfaces";

function wrap(): (props: { children: ReactNode }) => JSX.Element {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }) => <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

describe("useIntegrationSurfaces", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("calls GET /api/v1/integration-surfaces with appears_on param", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ items: [], total: 0 }), { status: 200 })
    );
    const { result } = renderHook(() => useIntegrationSurfaces({ appearsOn: "ops-integrations" }), {
      wrapper: wrap()
    });
    await waitFor(() => expect(result.current.data).toBeDefined());
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/integration-surfaces?appears_on=ops-integrations",
      expect.objectContaining({ credentials: "include" })
    );
  });

  it("returns the surfaces list", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            {
              id: "1",
              name: "surface-slack",
              integration_type: "slack",
              category: "integration",
              spec: { category: "integration", runtime: { kind: "spa", base_path: "/s/slack" }, display: { title: "Slack" } },
              active: true,
              registered_at: "2026-05-17T00:00:00Z",
              updated_at: "2026-05-17T00:00:00Z"
            }
          ],
          total: 1
        }),
        { status: 200 }
      )
    );
    const { result } = renderHook(() => useIntegrationSurfaces({ appearsOn: "ops-integrations" }), {
      wrapper: wrap()
    });
    await waitFor(() => expect(result.current.data?.items).toHaveLength(1));
    expect(result.current.data?.items[0].name).toBe("surface-slack");
  });
});
```

- [ ] **Step 2: Run — expect FAIL**

Run: `npm test -- src/lib/integration-surfaces/useIntegrationSurfaces.test.tsx`
Expected: FAIL.

- [ ] **Step 3: Implement useIntegrationSurfaces.ts**

```ts
import { useQuery } from "@tanstack/react-query";
import type { SlotID, IntegrationSurfacesListResponse } from "./types";

export interface UseIntegrationSurfacesOpts {
  appearsOn?: SlotID;
  integrationType?: string;
  category?: "integration" | "core" | "domain";
}

async function fetchSurfaces(opts: UseIntegrationSurfacesOpts): Promise<IntegrationSurfacesListResponse> {
  const params = new URLSearchParams();
  if (opts.appearsOn) params.set("appears_on", opts.appearsOn);
  if (opts.integrationType) params.set("integration_type", opts.integrationType);
  if (opts.category) params.set("category", opts.category);
  const qs = params.toString() ? `?${params.toString()}` : "";
  const resp = await fetch(`/api/v1/integration-surfaces${qs}`, { credentials: "include" });
  if (!resp.ok) {
    throw new Error(`${resp.status} ${resp.statusText}`);
  }
  return (await resp.json()) as IntegrationSurfacesListResponse;
}

export function useIntegrationSurfaces(opts: UseIntegrationSurfacesOpts) {
  return useQuery({
    queryKey: ["surfaces", opts],
    queryFn: () => fetchSurfaces(opts),
    staleTime: 5 * 60_000
  });
}
```

- [ ] **Step 4: Wire export**

Append to `src/lib/integration-surfaces/index.ts`:

```ts
export { useIntegrationSurfaces } from "./useIntegrationSurfaces";
export type { UseIntegrationSurfacesOpts } from "./useIntegrationSurfaces";
```

- [ ] **Step 5: Run — expect PASS**

Run: `npm test -- src/lib/integration-surfaces/useIntegrationSurfaces.test.tsx`
Expected: PASS — 2 tests.

- [ ] **Step 6: Commit**

```bash
git add src/lib/integration-surfaces
git commit -m "feat(surfaces): useIntegrationSurfaces hook — React Query over /api/v1/integration-surfaces"
```

---

## Task 3: IntegrationSurfaceCard component

**Files:**
- Create: `src/lib/integration-surfaces/IntegrationSurfaceCard.tsx`
- Create: `src/lib/integration-surfaces/IntegrationSurfaceCard.test.tsx`

- [ ] **Step 1: Write failing test**

`src/lib/integration-surfaces/IntegrationSurfaceCard.test.tsx`:

```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IntegrationSurfaceCard } from "./IntegrationSurfaceCard";
import type { IntegrationSurfaceManifestT } from "./types";

const m: IntegrationSurfaceManifestT = {
  id: "1",
  name: "surface-slack",
  integration_type: "slack",
  category: "integration",
  spec: {
    category: "integration",
    runtime: { kind: "spa", base_path: "/s/slack" },
    display: { title: "Slack", subtitle: "Workspace", icon: "slack", color_token: "brand.slack" }
  },
  active: true,
  registered_at: "2026-05-17T00:00:00Z",
  updated_at: "2026-05-17T00:00:00Z"
};

describe("IntegrationSurfaceCard", () => {
  it("renders title and subtitle", () => {
    render(<IntegrationSurfaceCard surface={m} />);
    expect(screen.getByText("Slack")).toBeInTheDocument();
    expect(screen.getByText("Workspace")).toBeInTheDocument();
  });

  it("navigates to base_path on click", async () => {
    const navigate = vi.fn();
    render(<IntegrationSurfaceCard surface={m} onClick={navigate} />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button"));
    expect(navigate).toHaveBeenCalledWith("/s/slack");
  });

  it("shows deprecated badge for inactive surfaces", () => {
    render(<IntegrationSurfaceCard surface={{ ...m, active: false }} />);
    expect(screen.getByText(/deprecated/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run — expect FAIL**

Run: `npm test -- IntegrationSurfaceCard.test.tsx`
Expected: FAIL.

- [ ] **Step 3: Implement IntegrationSurfaceCard.tsx**

```tsx
import { Card, CardActionArea, CardContent, Typography, Stack, Chip, Box } from "@mui/material";
import type { IntegrationSurfaceManifestT } from "./types";

export interface IntegrationSurfaceCardProps {
  surface: IntegrationSurfaceManifestT;
  onClick?: (basePath: string) => void;
}

const BRAND_COLOR: Record<string, { bg: string; fg: string }> = {
  "brand.slack": { bg: "#4A154B", fg: "#FFFFFF" },
  "brand.github": { bg: "#24292F", fg: "#FFFFFF" },
  "brand.grafana": { bg: "#F46800", fg: "#FFFFFF" },
  "brand.google-workspace": { bg: "#4285F4", fg: "#FFFFFF" },
  "brand.kubernetes": { bg: "#326CE5", fg: "#FFFFFF" },
  "brand.aws": { bg: "#FF9900", fg: "#0F172A" },
  "brand.secrets-management": { bg: "#5C6BC0", fg: "#FFFFFF" },
  "brand.webhooks-external": { bg: "#00ACC1", fg: "#FFFFFF" }
};

function badge(surface: IntegrationSurfaceManifestT): { label: string; color: "success" | "info" | "default" } | null {
  if (!surface.active) return { label: "Deprecated", color: "default" };
  const ageDaysReg = (Date.now() - new Date(surface.registered_at).getTime()) / 86400000;
  if (ageDaysReg < 7) return { label: "Novo", color: "success" };
  const ageHoursUpd = (Date.now() - new Date(surface.updated_at).getTime()) / 3600000;
  if (ageHoursUpd < 24) return { label: "Atualizado", color: "info" };
  return null;
}

export function IntegrationSurfaceCard({ surface, onClick }: IntegrationSurfaceCardProps) {
  const { display } = surface.spec;
  const palette = display.color_token ? BRAND_COLOR[display.color_token] : null;
  const b = badge(surface);
  const handleClick = () => {
    const path = surface.spec.runtime.base_path;
    if (onClick) {
      onClick(path);
    } else if (typeof window !== "undefined") {
      window.location.assign(path);
    }
  };
  return (
    <Card variant="outlined" sx={{ position: "relative", overflow: "hidden" }}>
      <CardActionArea onClick={handleClick}>
        {palette ? (
          <Box sx={{ height: 6, background: palette.bg }} />
        ) : (
          <Box sx={{ height: 6, background: "grey.300" }} />
        )}
        <CardContent>
          <Stack direction="row" spacing={1.5} alignItems="flex-start">
            {palette ? (
              <Box
                sx={{
                  width: 40,
                  height: 40,
                  borderRadius: 1,
                  background: palette.bg,
                  color: palette.fg,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontWeight: 700
                }}
              >
                {display.title.charAt(0)}
              </Box>
            ) : null}
            <Stack sx={{ flex: 1 }}>
              <Typography variant="h6">{display.title}</Typography>
              {display.subtitle ? (
                <Typography variant="caption" color="text.secondary">
                  {display.subtitle}
                </Typography>
              ) : null}
            </Stack>
            {b ? <Chip size="small" label={b.label} color={b.color} /> : null}
          </Stack>
        </CardContent>
      </CardActionArea>
    </Card>
  );
}
```

- [ ] **Step 4: Run — expect PASS**

Run: `npm test -- IntegrationSurfaceCard.test.tsx`
Expected: PASS — 3 tests.

- [ ] **Step 5: Wire export**

Append to `src/lib/integration-surfaces/index.ts`:

```ts
export { IntegrationSurfaceCard } from "./IntegrationSurfaceCard";
export type { IntegrationSurfaceCardProps } from "./IntegrationSurfaceCard";
```

- [ ] **Step 6: Commit**

```bash
git add src/lib/integration-surfaces
git commit -m "feat(surfaces): IntegrationSurfaceCard with brand palette + age badges"
```

---

## Task 4: IntegrationSurfaceSlot component

**Files:**
- Create: `src/lib/integration-surfaces/IntegrationSurfaceSlot.tsx`
- Create: `src/lib/integration-surfaces/IntegrationSurfaceSlot.test.tsx`

- [ ] **Step 1: Write failing test**

`src/lib/integration-surfaces/IntegrationSurfaceSlot.test.tsx`:

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { IntegrationSurfaceSlot } from "./IntegrationSurfaceSlot";
import type { IntegrationSurfaceManifestT } from "./types";
import type { ReactNode } from "react";

function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

const surfaces: IntegrationSurfaceManifestT[] = [
  {
    id: "1",
    name: "surface-slack",
    integration_type: "slack",
    category: "integration",
    spec: {
      category: "integration",
      runtime: { kind: "spa", base_path: "/s/slack" },
      display: { title: "Slack", appears_on: ["ops-integrations"] }
    },
    active: true,
    registered_at: "2026-05-17T00:00:00Z",
    updated_at: "2026-05-17T00:00:00Z"
  },
  {
    id: "2",
    name: "surface-github",
    integration_type: "github",
    category: "integration",
    spec: {
      category: "integration",
      runtime: { kind: "spa", base_path: "/s/github" },
      display: { title: "GitHub", appears_on: ["ops-integrations"] }
    },
    active: true,
    registered_at: "2026-05-17T00:00:00Z",
    updated_at: "2026-05-17T00:00:00Z"
  }
];

describe("IntegrationSurfaceSlot", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders one card per returned surface", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ items: surfaces, total: 2 }), { status: 200 })
    );
    wrap(<IntegrationSurfaceSlot slot="ops-integrations" />);
    await waitFor(() => expect(screen.getByText("Slack")).toBeInTheDocument());
    expect(screen.getByText("GitHub")).toBeInTheDocument();
  });

  it("renders default empty state when no surfaces", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ items: [], total: 0 }), { status: 200 })
    );
    wrap(<IntegrationSurfaceSlot slot="me" />);
    await waitFor(() =>
      expect(screen.getByText(/Nenhuma surface disponível/i)).toBeInTheDocument()
    );
  });

  it("renders custom empty state when provided", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ items: [], total: 0 }), { status: 200 })
    );
    wrap(<IntegrationSurfaceSlot slot="orgchart" emptyState={<div>Sem widgets</div>} />);
    await waitFor(() => expect(screen.getByText("Sem widgets")).toBeInTheDocument());
  });

  it("shows loading state during fetch", () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(() => new Promise(() => {})); // never resolves
    wrap(<IntegrationSurfaceSlot slot="console-home" />);
    expect(screen.getByRole("status")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run — expect FAIL**

Run: `npm test -- IntegrationSurfaceSlot.test.tsx`
Expected: FAIL.

- [ ] **Step 3: Implement IntegrationSurfaceSlot.tsx**

```tsx
import type { ReactNode } from "react";
import { Box, CircularProgress, Stack, Typography } from "@mui/material";
import { useIntegrationSurfaces } from "./useIntegrationSurfaces";
import { IntegrationSurfaceCard } from "./IntegrationSurfaceCard";
import type { SlotID } from "./types";

export interface IntegrationSurfaceSlotProps {
  slot: SlotID;
  layout?: "grid" | "list" | "inline";
  emptyState?: ReactNode;
}

const GAP = 16;

export function IntegrationSurfaceSlot({ slot, layout = "grid", emptyState }: IntegrationSurfaceSlotProps) {
  const { data, isLoading } = useIntegrationSurfaces({ appearsOn: slot });

  if (isLoading) {
    return (
      <Stack role="status" alignItems="center" sx={{ py: 4 }}>
        <CircularProgress size={28} />
      </Stack>
    );
  }
  if (!data || data.items.length === 0) {
    if (emptyState) return <>{emptyState}</>;
    return (
      <Box sx={{ py: 4, textAlign: "center" }}>
        <Typography variant="body2" color="text.secondary">
          Nenhuma surface disponível neste contexto
        </Typography>
      </Box>
    );
  }

  if (layout === "grid") {
    return (
      <Box
        sx={{
          display: "grid",
          gap: `${GAP}px`,
          gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))"
        }}
      >
        {data.items.map((s) => (
          <IntegrationSurfaceCard key={s.id} surface={s} />
        ))}
      </Box>
    );
  }
  if (layout === "list") {
    return (
      <Stack spacing={1}>
        {data.items.map((s) => (
          <IntegrationSurfaceCard key={s.id} surface={s} />
        ))}
      </Stack>
    );
  }
  // inline
  return (
    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
      {data.items.map((s) => (
        <Box key={s.id} sx={{ width: 280 }}>
          <IntegrationSurfaceCard surface={s} />
        </Box>
      ))}
    </Stack>
  );
}
```

- [ ] **Step 4: Wire export**

Append to `src/lib/integration-surfaces/index.ts`:

```ts
export { IntegrationSurfaceSlot } from "./IntegrationSurfaceSlot";
export type { IntegrationSurfaceSlotProps } from "./IntegrationSurfaceSlot";
```

- [ ] **Step 5: Run — expect PASS**

Run: `npm test -- IntegrationSurfaceSlot.test.tsx`
Expected: PASS — 4 tests.

- [ ] **Step 6: Commit**

```bash
git add src/lib/integration-surfaces
git commit -m "feat(surfaces): IntegrationSurfaceSlot renders cards by slot with layout variants"
```

---

## Task 5: useIntegrationSurfacesByMany hook (batch)

**Files:**
- Create: `src/lib/integration-surfaces/useIntegrationSurfacesByMany.ts`
- Create: `src/lib/integration-surfaces/useIntegrationSurfacesByMany.test.tsx`

- [ ] **Step 1: Write failing test**

`src/lib/integration-surfaces/useIntegrationSurfacesByMany.test.tsx`:

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useIntegrationSurfacesByMany } from "./useIntegrationSurfacesByMany";
import type { ReactNode } from "react";

function wrap() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
}

describe("useIntegrationSurfacesByMany", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("issues a single GET with comma-joined slots and partitions response by slot", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            {
              id: "1",
              name: "surface-a",
              integration_type: null,
              category: "core",
              spec: {
                category: "core",
                runtime: { kind: "spa", base_path: "/s/a" },
                display: { title: "A", appears_on: ["console-home"] }
              },
              active: true,
              registered_at: "2026-05-17T00:00:00Z",
              updated_at: "2026-05-17T00:00:00Z"
            },
            {
              id: "2",
              name: "surface-b",
              integration_type: null,
              category: "core",
              spec: {
                category: "core",
                runtime: { kind: "spa", base_path: "/s/b" },
                display: { title: "B", appears_on: ["me"] }
              },
              active: true,
              registered_at: "2026-05-17T00:00:00Z",
              updated_at: "2026-05-17T00:00:00Z"
            }
          ],
          total: 2
        }),
        { status: 200 }
      )
    );
    const { result } = renderHook(() => useIntegrationSurfacesByMany(["console-home", "me"]), { wrapper: wrap() });
    await waitFor(() => expect(result.current.data).toBeDefined());
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/integration-surfaces?appears_on=console-home,me",
      expect.objectContaining({ credentials: "include" })
    );
    const partitioned = result.current.data!;
    expect(partitioned["console-home"]).toHaveLength(1);
    expect(partitioned["console-home"][0].name).toBe("surface-a");
    expect(partitioned["me"]).toHaveLength(1);
    expect(partitioned["me"][0].name).toBe("surface-b");
  });
});
```

- [ ] **Step 2: Run — expect FAIL**

Run: `npm test -- useIntegrationSurfacesByMany.test.tsx`
Expected: FAIL.

- [ ] **Step 3: Implement useIntegrationSurfacesByMany.ts**

```ts
import { useQuery } from "@tanstack/react-query";
import type { SlotID, IntegrationSurfaceManifestT, IntegrationSurfacesListResponse } from "./types";

async function fetchMany(slots: SlotID[]): Promise<Record<SlotID, IntegrationSurfaceManifestT[]>> {
  if (slots.length === 0) {
    return {} as Record<SlotID, IntegrationSurfaceManifestT[]>;
  }
  const qs = `?appears_on=${slots.join(",")}`;
  const resp = await fetch(`/api/v1/integration-surfaces${qs}`, { credentials: "include" });
  if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}`);
  const body = (await resp.json()) as IntegrationSurfacesListResponse;
  const out = {} as Record<SlotID, IntegrationSurfaceManifestT[]>;
  for (const slot of slots) {
    out[slot] = body.items.filter((m) => (m.spec.display.appears_on ?? []).includes(slot));
  }
  return out;
}

export function useIntegrationSurfacesByMany(slots: SlotID[]) {
  return useQuery({
    queryKey: ["surfaces", "by-many", slots.slice().sort()],
    queryFn: () => fetchMany(slots),
    staleTime: 5 * 60_000
  });
}
```

- [ ] **Step 4: Wire export**

Append to `src/lib/integration-surfaces/index.ts`:

```ts
export { useIntegrationSurfacesByMany } from "./useIntegrationSurfacesByMany";
```

- [ ] **Step 5: Run — expect PASS**

Run: `npm test -- useIntegrationSurfacesByMany.test.tsx`
Expected: PASS — 1 test.

- [ ] **Step 6: Commit**

```bash
git add src/lib/integration-surfaces
git commit -m "feat(surfaces): useIntegrationSurfacesByMany batches multiple slot fetches"
```

---

## Task 6: Refactor /ops/integrations to use IntegrationSurfaceSlot

**Files:**
- Modify: `src/pages/ops/IntegrationsPage.tsx` (or the existing path; locate via grep)
- Tests: ensure existing tests still pass; add new test for the IntegrationSurfaceSlot integration

- [ ] **Step 1: Locate the existing page**

```bash
grep -rn "ops/integrations\|IntegrationsPage" src/ --include='*.tsx' | head -5
```

- [ ] **Step 2: Write failing test for IntegrationSurfaceSlot integration**

Append to existing test file (e.g., `src/pages/ops/IntegrationsPage.test.tsx`):

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { IntegrationsPage } from "./IntegrationsPage";

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>{ui}</QueryClientProvider>
    </MemoryRouter>
  );
}

describe("IntegrationsPage with IntegrationSurfaceSlot", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders a card from /api/v1/integration-surfaces?appears_on=ops-integrations", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/api/v1/integration-surfaces")) {
        return new Response(
          JSON.stringify({
            items: [
              {
                id: "1",
                name: "surface-slack",
                integration_type: "slack",
                category: "integration",
                spec: {
                  category: "integration",
                  runtime: { kind: "spa", base_path: "/s/slack" },
                  display: { title: "Slack", appears_on: ["ops-integrations"] }
                },
                active: true,
                registered_at: "2026-05-17T00:00:00Z",
                updated_at: "2026-05-17T00:00:00Z"
              }
            ],
            total: 1
          }),
          { status: 200 }
        );
      }
      // Fallback for other endpoints the page uses
      return new Response("[]", { status: 200 });
    });
    wrap(<IntegrationsPage />);
    await waitFor(() => expect(screen.getByText("Slack")).toBeInTheDocument());
  });
});
```

- [ ] **Step 3: Run — expect FAIL initially (page doesn't render IntegrationSurfaceSlot yet)**

Run: `npm test -- IntegrationsPage.test.tsx`
Expected: FAIL on the new test.

- [ ] **Step 4: Modify IntegrationsPage**

Open `src/pages/ops/IntegrationsPage.tsx`. Locate the existing integration_type grid render and replace it (or add alongside, with fallback) with `<IntegrationSurfaceSlot slot="ops-integrations" layout="grid"/>`. Example shape:

```tsx
import { IntegrationSurfaceSlot } from "../../lib/surfaces";
// ... existing imports ...

export function IntegrationsPage() {
  return (
    <Box sx={{ p: 3 }}>
      <PageHeader title="Integrações" subtitle="Console de instâncias e adapters" />
      <Stack spacing={3}>
        <Section title="Surfaces disponíveis">
          <IntegrationSurfaceSlot slot="ops-integrations" layout="grid" />
        </Section>
        {/* Existing fallback grid for integration_types without surfaces — keep it */}
        <Section title="Adapters sem surface">
          <LegacyIntegrationTypesGrid />
        </Section>
      </Stack>
    </Box>
  );
}
```

Adapt to existing component/JSX. Preserve "+ Nova instância" action.

- [ ] **Step 5: Run — expect PASS**

Run: `npm test -- IntegrationsPage.test.tsx`
Expected: PASS (new + existing tests).

- [ ] **Step 6: Commit**

```bash
git add src/pages/ops
git commit -m "feat(ops): /ops/integrations renders IntegrationSurfaceSlot with adapter fallback grid"
```

---

## Task 7: Add IntegrationSurfaceSlot to home page

**Files:**
- Modify: home page component (`src/pages/HomePage.tsx` or `src/pages/index.tsx`; locate via grep)

- [ ] **Step 1: Locate**

```bash
grep -rn "path=\"/\"\|HomePage\|index\b" src/App.tsx src/pages/*.tsx 2>/dev/null | head -10
```

- [ ] **Step 2: Write failing test**

If the home page has a tests file, append:

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { HomePage } from "./HomePage";

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>{ui}</QueryClientProvider>
    </MemoryRouter>
  );
}

describe("HomePage with console-home IntegrationSurfaceSlot", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders cards from /api/v1/integration-surfaces?appears_on=console-home", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            {
              id: "h1",
              name: "surface-home-pin",
              integration_type: null,
              category: "core",
              spec: {
                category: "core",
                runtime: { kind: "spa", base_path: "/s/x" },
                display: { title: "Pinned", appears_on: ["console-home"] }
              },
              active: true,
              registered_at: "2026-05-17T00:00:00Z",
              updated_at: "2026-05-17T00:00:00Z"
            }
          ],
          total: 1
        }),
        { status: 200 }
      )
    );
    wrap(<HomePage />);
    await waitFor(() => expect(screen.getByText("Pinned")).toBeInTheDocument());
  });
});
```

- [ ] **Step 3: Run — expect FAIL**

Run: `npm test -- HomePage.test.tsx`
Expected: FAIL.

- [ ] **Step 4: Add IntegrationSurfaceSlot to home**

Edit home page component. Below the welcome/hero section, add:

```tsx
import { IntegrationSurfaceSlot } from "../lib/surfaces";

// ...inside HomePage component, after existing hero block:
<Box sx={{ mt: 4 }}>
  <Typography variant="h6" gutterBottom>
    Atalhos
  </Typography>
  <IntegrationSurfaceSlot slot="console-home" layout="grid" />
</Box>
```

- [ ] **Step 5: Run — expect PASS**

Run: `npm test -- HomePage.test.tsx`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/pages
git commit -m "feat(home): render console-home IntegrationSurfaceSlot below hero"
```

---

## Task 8: Add IntegrationSurfaceSlot to collaborator detail page

**Files:**
- Modify: `src/pages/collaborators/CollaboratorDetailPage.tsx` (or actual path)

- [ ] **Step 1: Locate**

```bash
grep -rn "colaboradores\|CollaboratorDetail" src/ --include='*.tsx' | head -10
```

- [ ] **Step 2: Write failing test**

Append to `CollaboratorDetailPage.test.tsx`:

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { CollaboratorDetailPage } from "./CollaboratorDetailPage";

function wrap(initialPath: string, ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <QueryClientProvider client={qc}>
        <Routes>
          <Route path="/colaboradores/:id" element={ui} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>
  );
}

describe("CollaboratorDetailPage with colaborador-detail slot", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders IntegrationSurfaceSlot for colaborador-detail", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes("/api/v1/integration-surfaces?appears_on=colaborador-detail")) {
        return new Response(
          JSON.stringify({
            items: [
              {
                id: "cd1",
                name: "surface-grafana",
                integration_type: "grafana",
                category: "integration",
                spec: {
                  category: "integration",
                  runtime: { kind: "spa", base_path: "/s/grafana" },
                  display: { title: "Grafana", appears_on: ["colaborador-detail"] }
                },
                active: true,
                registered_at: "2026-05-17T00:00:00Z",
                updated_at: "2026-05-17T00:00:00Z"
              }
            ],
            total: 1
          }),
          { status: 200 }
        );
      }
      // Fallback for collaborator detail endpoint
      return new Response(
        JSON.stringify({ id: "abc", name: "Alice", email: "alice@dakasa.me" }),
        { status: 200 }
      );
    });
    wrap("/colaboradores/abc", <CollaboratorDetailPage />);
    await waitFor(() => expect(screen.getByText("Grafana")).toBeInTheDocument());
  });
});
```

- [ ] **Step 3: Run — expect FAIL**

Run: `npm test -- CollaboratorDetailPage.test.tsx`
Expected: FAIL on the new test.

- [ ] **Step 4: Modify CollaboratorDetailPage**

Append a section to the page:

```tsx
import { IntegrationSurfaceSlot } from "../../lib/surfaces";

// ...inside the component, below existing detail blocks:
<Box sx={{ mt: 3 }}>
  <Typography variant="h6" gutterBottom>
    Sistemas vinculados
  </Typography>
  <IntegrationSurfaceSlot slot="colaborador-detail" layout="inline" />
</Box>
```

- [ ] **Step 5: Run — expect PASS**

Run: `npm test -- CollaboratorDetailPage.test.tsx`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/pages/collaborators
git commit -m "feat(colaborador): render colaborador-detail IntegrationSurfaceSlot under sistemas vinculados"
```

---

## Task 9: Build + smoke

**Files:** none (build only)

- [ ] **Step 1: Run full test suite**

```bash
cd /Users/dakasa/projects/yggdrasil/surface-console
npm test -- --run
```

Expected: all tests PASS (existing + new ~13 surface-related tests).

- [ ] **Step 2: Build**

```bash
npm run build
```

Expected: clean build, no warnings about missing imports.

- [ ] **Step 3: Start dev server and verify visually (manual smoke)**

```bash
npm run dev
```

In browser visit:
- `http://localhost:5173/ops/integrations` — should show "Nenhuma surface disponível" (correct empty state until Phase 1)
- `http://localhost:5173/` — should show "Atalhos" section with empty state
- `http://localhost:5173/colaboradores/<any>` — should show "Sistemas vinculados" section with empty state

(All slots empty because Phase 0b deployment hasn't shipped to local yet, OR because no surface is registered yet — both are normal pre-Phase 1.)

- [ ] **Step 4: Commit sync gate**

```bash
git commit --allow-empty -m "chore: Phase 0c complete — IntegrationSurfaceSlot wired in console pages"
```

---

## Phase 0c sync gate (after Task 9)

Before Phase 1 surfaces will visually appear in console:

1. ✅ All vitest tests passing (existing + new)
2. ✅ Build clean (no missing modules, no TS errors)
3. ✅ Three pages show IntegrationSurfaceSlot in empty state (until surfaces deploy)
4. ✅ Network: GET `/api/v1/integration-surfaces?appears_on=...` returns from Phase 0b backend (200 even with `items: []`)

---

## Final code reviewer dispatch (after Task 9)

After all tasks complete, dispatch one final code reviewer. Reviewer checks:

- All hooks use `useQuery` and respect `staleTime: 5 * 60_000` for slot lookups
- `IntegrationSurfaceCard` falls back to grey palette when `color_token` is unknown
- `window.location.assign` used (NOT React Router push) — full-page nav per spec §5.3
- No leak of `instance_id` into URL (slot cards link to `base_path` only; instance selection is per-surface)
- Permission filtering deferred to backend (`/api/v1/integration-surfaces` already filters by session role) — no client-side `core_contracts` parsing in V1
- `useIntegrationSurfacesByMany` partitions correctly when a surface declares multiple slots
- `IntegrationsPage` still shows "+ Nova instância" action and adapter fallback grid

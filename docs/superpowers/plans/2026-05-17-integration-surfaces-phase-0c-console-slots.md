# Integration Surfaces — Phase 0c: surface-console IntegrationSurfaceSlot Implementation Plan (REVISED 2026-05-18)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `IntegrationSurfaceSlot` / `IntegrationSurfaceCard` rendering machinery to `surface-console` (plain CSS, NOT MUI) and integrate into three existing pages: `OverviewPage` (`/`), `OpsIntegrationsPage` (`/ops/integrations`), `CollaboratorDetailPage` (`/collaborators/:id`).

**Real codebase patterns used** (verified 2026-05-18 via deep inspection):
- UI primitives: plain CSS modules with `casa-tokens.css` design tokens. No `@mui/material`. Class-naming `casa-*` for shared, `<component>-*` for component-specific.
- Pages have varying props: `OverviewPage({canSeeOps})`, `OpsIntegrationsPage({canSeeOps, userName})`, `CollaboratorDetailPage()` (uses `useParams`).
- Data fetching: `@tanstack/react-query` + `requestJSON()` helper from `src/lib/api.ts` (`credentials: "include"` for SSO cookie).
- Testing: Vitest + Testing Library + jsdom; tests wrap in `MemoryRouter` + `QueryClientProvider`; mock modules via `vi.mock()`.
- Icons: inline SVGs + brand logos from `/public/brand/<id>.svg`.
- Existing `src/lib/surfaces/` is vestigial (not used at runtime) — safe to add `src/lib/integration-surfaces/` alongside.
- `src/setupTests.ts` imports `@testing-library/jest-dom/vitest`.

**Tech Stack:** React 19 + TypeScript + Vite, vitest, @tanstack/react-query v5, plain CSS.

**Spec reference:** `/Users/dakasa/projects/yggdrasil/yggdrasil-core/docs/superpowers/specs/2026-05-17-integration-surfaces-design.md` §5.

**Working directory:** `/Users/dakasa/projects/yggdrasil/surface-console/`. Push direct to `main`. No co-author trailers.

---

## Task 1: Module bootstrap + types

**Files:**
- Create: `src/lib/integration-surfaces/types.ts`
- Create: `src/lib/integration-surfaces/index.ts`
- Create: `src/lib/integration-surfaces/types.test.ts`

- [ ] **Step 1: Failing test**

`src/lib/integration-surfaces/types.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { isSlotID, type SlotID, type IntegrationSurfaceManifestT } from "./types";

describe("isSlotID", () => {
  it("recognises 6 known slots", () => {
    const known: SlotID[] = ["console-home", "ops-integrations", "me", "equipe", "orgchart", "colaborador-detail"];
    known.forEach((s) => expect(isSlotID(s)).toBe(true));
  });
  it("rejects unknown strings", () => {
    expect(isSlotID("random")).toBe(false);
  });
});

describe("IntegrationSurfaceManifestT shape", () => {
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
```

- [ ] **Step 2: Run — expect FAIL**

`npm run test:run -- src/lib/integration-surfaces/types.test.ts`

Expected: module not found.

- [ ] **Step 3: Implement types.ts**

```ts
export type SlotID =
  | "console-home"
  | "ops-integrations"
  | "me"
  | "equipe"
  | "orgchart"
  | "colaborador-detail";

const KNOWN: SlotID[] = ["console-home", "ops-integrations", "me", "equipe", "orgchart", "colaborador-detail"];

export function isSlotID(value: string): value is SlotID {
  return (KNOWN as readonly string[]).includes(value);
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

- [ ] **Step 4: index.ts**

```ts
export * from "./types";
```

- [ ] **Step 5: Run — expect PASS**

Expected: 3 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/lib/integration-surfaces
git commit -m "feat(integration-surfaces): types module — IntegrationSurfaceManifestT, SlotID, isSlotID"
```

---

## Task 2: useIntegrationSurfaces hook

**Files:**
- Create: `src/lib/integration-surfaces/useIntegrationSurfaces.ts`
- Create: `src/lib/integration-surfaces/useIntegrationSurfaces.test.tsx`

- [ ] **Step 1: Inspect the existing API client**

```bash
sed -n '1,40p' src/lib/api.ts
```

Confirm `requestJSON<T>(path, init?)` exists. We'll add a new function in the same file.

- [ ] **Step 2: Add `fetchIntegrationSurfaces` to `src/lib/api.ts`**

Edit `src/lib/api.ts` and append (after other `fetch*` functions):

```ts
import type { IntegrationSurfacesListResponse, SlotID } from "./integration-surfaces/types";

export interface FetchIntegrationSurfacesOpts {
  appearsOn?: SlotID;
  integrationType?: string;
  category?: "integration" | "core" | "domain";
}

export async function fetchIntegrationSurfaces(
  opts: FetchIntegrationSurfacesOpts = {}
): Promise<IntegrationSurfacesListResponse> {
  const params = new URLSearchParams();
  if (opts.appearsOn) params.set("appears_on", opts.appearsOn);
  if (opts.integrationType) params.set("integration_type", opts.integrationType);
  if (opts.category) params.set("category", opts.category);
  const qs = params.toString() ? `?${params.toString()}` : "";
  return requestJSON<IntegrationSurfacesListResponse>(`/api/v1/integration-surfaces${qs}`);
}
```

- [ ] **Step 3: Failing test**

`src/lib/integration-surfaces/useIntegrationSurfaces.test.tsx`:

```tsx
import { describe, it, expect, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useIntegrationSurfaces } from "./useIntegrationSurfaces";

vi.mock("../api", () => ({
  fetchIntegrationSurfaces: vi.fn().mockResolvedValue({
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
  })
}));

function wrap() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
}

describe("useIntegrationSurfaces", () => {
  it("calls fetchIntegrationSurfaces with appearsOn opt", async () => {
    const { result } = renderHook(() => useIntegrationSurfaces({ appearsOn: "ops-integrations" }), {
      wrapper: wrap()
    });
    await waitFor(() => expect(result.current.data).toBeDefined());
    expect(result.current.data?.items[0].name).toBe("surface-slack");
  });
});
```

- [ ] **Step 4: Run — expect FAIL**

`npm run test:run -- useIntegrationSurfaces.test.tsx`

Expected: module not found.

- [ ] **Step 5: Implement useIntegrationSurfaces.ts**

```ts
import { useQuery } from "@tanstack/react-query";
import {
  fetchIntegrationSurfaces,
  type FetchIntegrationSurfacesOpts
} from "../api";
import type { IntegrationSurfacesListResponse } from "./types";

export type UseIntegrationSurfacesOpts = FetchIntegrationSurfacesOpts;

export function useIntegrationSurfaces(opts: UseIntegrationSurfacesOpts = {}) {
  return useQuery<IntegrationSurfacesListResponse>({
    queryKey: ["integration-surfaces", opts],
    queryFn: () => fetchIntegrationSurfaces(opts),
    staleTime: 5 * 60_000
  });
}
```

- [ ] **Step 6: Export from index.ts**

Append to `src/lib/integration-surfaces/index.ts`:

```ts
export { useIntegrationSurfaces, type UseIntegrationSurfacesOpts } from "./useIntegrationSurfaces";
```

- [ ] **Step 7: Run — expect PASS**

Expected: 1 test PASS.

- [ ] **Step 8: Commit**

```bash
git add src/lib/integration-surfaces src/lib/api.ts
git commit -m "feat(integration-surfaces): useIntegrationSurfaces hook + fetchIntegrationSurfaces api"
```

---

## Task 3: IntegrationSurfaceCard component

**Files:**
- Create: `src/lib/integration-surfaces/IntegrationSurfaceCard.tsx`
- Create: `src/lib/integration-surfaces/IntegrationSurfaceCard.css`
- Create: `src/lib/integration-surfaces/IntegrationSurfaceCard.test.tsx`

- [ ] **Step 1: Inspect an existing card for the casa-* pattern**

```bash
sed -n '1,60p' src/pages/ops/OpsIntegrationsPage.css 2>/dev/null | grep -A 5 "conn-card"
```

Note the BEM-ish naming (`.conn-card__logo`, `.conn-card__body`, `.conn-card__right`).

- [ ] **Step 2: Failing test**

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
    display: { title: "Slack", subtitle: "Workspace", icon: "slack" }
  },
  active: true,
  registered_at: "2026-05-17T00:00:00Z",
  updated_at: "2026-05-17T00:00:00Z"
};

describe("IntegrationSurfaceCard", () => {
  it("renders title + subtitle", () => {
    render(<IntegrationSurfaceCard surface={m} />);
    expect(screen.getByText("Slack")).toBeInTheDocument();
    expect(screen.getByText("Workspace")).toBeInTheDocument();
  });

  it("invokes onClick with base_path", async () => {
    const handle = vi.fn();
    render(<IntegrationSurfaceCard surface={m} onClick={handle} />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("link", { name: /Slack/i }));
    expect(handle).toHaveBeenCalledWith("/s/slack");
  });

  it("shows deprecated badge when inactive", () => {
    render(<IntegrationSurfaceCard surface={{ ...m, active: false }} />);
    expect(screen.getByText(/deprecated/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 3: Run — expect FAIL**

`npm run test:run -- IntegrationSurfaceCard.test.tsx`

Expected: module not found.

- [ ] **Step 4: Implement IntegrationSurfaceCard.tsx**

```tsx
import "./IntegrationSurfaceCard.css";
import type { IntegrationSurfaceManifestT } from "./types";

export interface IntegrationSurfaceCardProps {
  surface: IntegrationSurfaceManifestT;
  onClick?: (basePath: string) => void;
}

function badge(s: IntegrationSurfaceManifestT): { label: string; modifier: string } | null {
  if (!s.active) return { label: "Deprecated", modifier: "is-deprecated" };
  const ageDaysReg = (Date.now() - new Date(s.registered_at).getTime()) / 86400000;
  if (ageDaysReg < 7) return { label: "Novo", modifier: "is-new" };
  const ageHoursUpd = (Date.now() - new Date(s.updated_at).getTime()) / 3600000;
  if (ageHoursUpd < 24) return { label: "Atualizado", modifier: "is-updated" };
  return null;
}

function logoSrc(name: string | undefined, integrationType: string | null): string | null {
  if (name) return `/brand/${name.toLowerCase()}.svg`;
  if (integrationType) return `/brand/${integrationType.toLowerCase()}.svg`;
  return null;
}

export function IntegrationSurfaceCard({ surface, onClick }: IntegrationSurfaceCardProps) {
  const { display, runtime } = surface.spec;
  const b = badge(surface);
  const logo = logoSrc(display.icon, surface.integration_type);
  const initial = display.title.charAt(0).toUpperCase();

  const handleClick = (e: React.MouseEvent<HTMLAnchorElement>) => {
    if (onClick) {
      e.preventDefault();
      onClick(runtime.base_path);
    }
    // Otherwise the <a href> handles full-page navigation natively.
  };

  return (
    <a
      className="integration-surface-card"
      href={runtime.base_path}
      onClick={handleClick}
      aria-label={display.title}
    >
      <div className="integration-surface-card__logo">
        {logo ? (
          <img
            src={logo}
            alt=""
            onError={(e) => {
              (e.currentTarget as HTMLImageElement).style.display = "none";
            }}
          />
        ) : null}
        <span className="integration-surface-card__initial">{initial}</span>
      </div>
      <div className="integration-surface-card__body">
        <strong className="integration-surface-card__title">{display.title}</strong>
        {display.subtitle ? (
          <span className="integration-surface-card__subtitle">{display.subtitle}</span>
        ) : null}
      </div>
      {b ? (
        <span className={`integration-surface-card__badge ${b.modifier}`}>{b.label}</span>
      ) : null}
    </a>
  );
}
```

- [ ] **Step 5: Implement IntegrationSurfaceCard.css**

```css
.integration-surface-card {
  display: grid;
  grid-template-columns: 56px 1fr auto;
  gap: var(--sp-3, 12px);
  align-items: center;
  padding: var(--sp-4, 16px);
  border: 1px solid var(--rule-soft, rgba(255, 255, 255, 0.1));
  border-radius: var(--r-3, 12px);
  background: var(--color-bg-surface, #0f1014);
  color: var(--color-ink-primary, #f4f8f7);
  text-decoration: none;
  transition: border-color var(--dur-fast, 150ms) var(--ease-soft, ease),
              transform var(--dur-fast, 150ms) var(--ease-soft, ease);
}
.integration-surface-card:hover {
  border-color: var(--color-clay, #4fd1c5);
  transform: translateY(-1px);
}
.integration-surface-card:focus-visible {
  outline: 2px solid var(--color-clay, #4fd1c5);
  outline-offset: 2px;
}

.integration-surface-card__logo {
  position: relative;
  width: 56px;
  height: 56px;
  border-radius: var(--r-2, 8px);
  background: var(--color-bg-deep, #050607);
  display: flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
}
.integration-surface-card__logo img {
  max-width: 60%;
  max-height: 60%;
  position: relative;
  z-index: 1;
}
.integration-surface-card__initial {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 1.4rem;
  color: var(--color-ink-primary, #f4f8f7);
  opacity: 0.6;
  z-index: 0;
}

.integration-surface-card__body {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: var(--sp-1, 4px);
}
.integration-surface-card__title {
  font-weight: 600;
  font-size: var(--fs-body, 1rem);
  color: var(--color-ink-primary, #f4f8f7);
}
.integration-surface-card__subtitle {
  font-size: var(--fs-caption, 0.8125rem);
  color: var(--color-ink-secondary, rgba(244, 248, 247, 0.65));
  line-height: 1.4;
}

.integration-surface-card__badge {
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 0.75rem;
  font-weight: 500;
  white-space: nowrap;
}
.integration-surface-card__badge.is-new {
  background: rgba(79, 209, 197, 0.16);
  color: var(--color-clay, #4fd1c5);
}
.integration-surface-card__badge.is-updated {
  background: rgba(125, 144, 255, 0.16);
  color: #9aabff;
}
.integration-surface-card__badge.is-deprecated {
  background: rgba(160, 160, 160, 0.16);
  color: rgba(244, 248, 247, 0.5);
}
```

- [ ] **Step 6: Run — expect PASS**

Expected: 3 tests PASS.

- [ ] **Step 7: Wire export**

Append to `src/lib/integration-surfaces/index.ts`:

```ts
export { IntegrationSurfaceCard, type IntegrationSurfaceCardProps } from "./IntegrationSurfaceCard";
```

- [ ] **Step 8: Commit**

```bash
git add src/lib/integration-surfaces
git commit -m "feat(integration-surfaces): IntegrationSurfaceCard + plain CSS (casa-tokens)"
```

---

## Task 4: IntegrationSurfaceSlot component

**Files:**
- Create: `src/lib/integration-surfaces/IntegrationSurfaceSlot.tsx`
- Create: `src/lib/integration-surfaces/IntegrationSurfaceSlot.css`
- Create: `src/lib/integration-surfaces/IntegrationSurfaceSlot.test.tsx`

- [ ] **Step 1: Failing test**

`src/lib/integration-surfaces/IntegrationSurfaceSlot.test.tsx`:

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { IntegrationSurfaceSlot } from "./IntegrationSurfaceSlot";

const mockFetch = vi.fn();
vi.mock("../api", () => ({
  fetchIntegrationSurfaces: (...args: unknown[]) => mockFetch(...args)
}));

function wrap(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

beforeEach(() => {
  mockFetch.mockReset();
});

describe("IntegrationSurfaceSlot", () => {
  it("renders cards for results", async () => {
    mockFetch.mockResolvedValue({
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
    });
    wrap(<IntegrationSurfaceSlot slot="ops-integrations" />);
    await waitFor(() => expect(screen.getByText("Slack")).toBeInTheDocument());
  });

  it("renders default empty state", async () => {
    mockFetch.mockResolvedValue({ items: [], total: 0 });
    wrap(<IntegrationSurfaceSlot slot="me" />);
    await waitFor(() =>
      expect(screen.getByText(/Nenhuma surface disponível/i)).toBeInTheDocument()
    );
  });

  it("renders custom empty state when provided", async () => {
    mockFetch.mockResolvedValue({ items: [], total: 0 });
    wrap(<IntegrationSurfaceSlot slot="orgchart" emptyState={<div>Sem widgets</div>} />);
    await waitFor(() => expect(screen.getByText("Sem widgets")).toBeInTheDocument());
  });
});
```

- [ ] **Step 2: Run — expect FAIL**

Expected: module not found.

- [ ] **Step 3: Implement IntegrationSurfaceSlot.tsx**

```tsx
import "./IntegrationSurfaceSlot.css";
import type { ReactNode } from "react";
import { useIntegrationSurfaces } from "./useIntegrationSurfaces";
import { IntegrationSurfaceCard } from "./IntegrationSurfaceCard";
import type { SlotID } from "./types";

export interface IntegrationSurfaceSlotProps {
  slot: SlotID;
  layout?: "grid" | "list" | "inline";
  emptyState?: ReactNode;
}

export function IntegrationSurfaceSlot({
  slot,
  layout = "grid",
  emptyState
}: IntegrationSurfaceSlotProps) {
  const { data, isLoading, error } = useIntegrationSurfaces({ appearsOn: slot });

  if (isLoading) {
    return (
      <div className="integration-surface-slot__loading" role="status">
        Carregando surfaces…
      </div>
    );
  }

  if (error) {
    return (
      <div className="integration-surface-slot__error">
        Não foi possível carregar surfaces para esta seção.
      </div>
    );
  }

  if (!data || data.items.length === 0) {
    if (emptyState) return <>{emptyState}</>;
    return (
      <div className="integration-surface-slot__empty">
        Nenhuma surface disponível neste contexto.
      </div>
    );
  }

  return (
    <div className={`integration-surface-slot integration-surface-slot--${layout}`}>
      {data.items.map((s) => (
        <IntegrationSurfaceCard key={s.id} surface={s} />
      ))}
    </div>
  );
}
```

- [ ] **Step 4: Implement IntegrationSurfaceSlot.css**

```css
.integration-surface-slot {
  display: grid;
  gap: var(--sp-3, 12px);
}
.integration-surface-slot--grid {
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
}
.integration-surface-slot--list {
  grid-template-columns: 1fr;
}
.integration-surface-slot--inline {
  display: flex;
  flex-wrap: wrap;
  gap: var(--sp-3, 12px);
}
.integration-surface-slot--inline > * {
  width: 280px;
}

.integration-surface-slot__loading,
.integration-surface-slot__empty,
.integration-surface-slot__error {
  padding: var(--sp-5, 24px);
  text-align: center;
  border-radius: var(--r-3, 12px);
  border: 1px dashed var(--rule-soft, rgba(255, 255, 255, 0.12));
  background: var(--color-bg-surface, #0f1014);
  color: var(--color-ink-secondary, rgba(244, 248, 247, 0.65));
}
.integration-surface-slot__error {
  border-color: rgba(239, 68, 68, 0.5);
  color: #ef4444;
}
```

- [ ] **Step 5: Run — expect PASS**

Expected: 3 tests PASS.

- [ ] **Step 6: Wire export**

Append to `src/lib/integration-surfaces/index.ts`:

```ts
export { IntegrationSurfaceSlot, type IntegrationSurfaceSlotProps } from "./IntegrationSurfaceSlot";
```

- [ ] **Step 7: Commit**

```bash
git add src/lib/integration-surfaces
git commit -m "feat(integration-surfaces): IntegrationSurfaceSlot with grid/list/inline layouts"
```

---

## Task 5: Integrate into OpsIntegrationsPage

**Files:**
- Modify: `src/pages/ops/OpsIntegrationsPage.tsx`
- Modify: `src/pages/ops/OpsIntegrationsPage.test.tsx` (or add test if not exists)

- [ ] **Step 1: Inspect current page**

```bash
sed -n '1,60p' src/pages/ops/OpsIntegrationsPage.tsx
```

Note: receives `{ canSeeOps, userName }` props; uses `useQuery` for `["ops-surfaces"]` (OLD system); uses `TopBar zone="ops"`. We add a NEW SECTION to the page, NOT replace anything.

- [ ] **Step 2: Failing test (or new test if file doesn't exist)**

Append to `src/pages/ops/OpsIntegrationsPage.test.tsx` (create if missing):

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { OpsIntegrationsPage } from "./OpsIntegrationsPage";

vi.mock("../../lib/api", () => ({
  fetchIntegrationSurfaces: vi.fn().mockResolvedValue({
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
  // Existing API mocks needed by the page — fill in as required:
  listSurfaces: vi.fn().mockResolvedValue([]),
  listSurfaceTargets: vi.fn().mockResolvedValue([]),
  // ... add other existing fetches the page calls
}));

vi.mock("../../lib/auth/useAuthSession", () => ({
  useAuthSession: () => ({ session: { displayName: "Test User" } })
}));

function setup() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <OpsIntegrationsPage canSeeOps={true} userName="Test User" />
      </QueryClientProvider>
    </MemoryRouter>
  );
}

describe("OpsIntegrationsPage with IntegrationSurfaceSlot", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders the Surfaces section heading", async () => {
    setup();
    await waitFor(() =>
      expect(screen.getByText(/Surfaces em execução/i)).toBeInTheDocument()
    );
  });

  it("renders a card from /api/v1/integration-surfaces", async () => {
    setup();
    await waitFor(() => expect(screen.getByText("Slack")).toBeInTheDocument());
  });
});
```

- [ ] **Step 3: Run — expect FAIL**

`npm run test:run -- OpsIntegrationsPage.test.tsx`

Expected: "Surfaces em execução" not found.

- [ ] **Step 4: Modify the page**

In `src/pages/ops/OpsIntegrationsPage.tsx`, add the import:

```tsx
import { IntegrationSurfaceSlot } from "../../lib/integration-surfaces";
```

Add a new section AFTER the existing `ops-integrations__settings` section (and before the page closes):

```tsx
<section className="ops-page-section" aria-label="Surfaces em execução">
  <header className="ops-page-section__header">
    <h2>Surfaces em execução</h2>
    <p className="casa-overline">Surfaces federadas registradas no catálogo</p>
  </header>
  <IntegrationSurfaceSlot slot="ops-integrations" layout="grid" />
</section>
```

If `.ops-page-section` doesn't exist in CSS, add to `OpsIntegrationsPage.css`:

```css
.ops-page-section {
  margin-top: var(--sp-6, 32px);
}
.ops-page-section__header {
  display: flex;
  flex-direction: column;
  gap: var(--sp-1, 4px);
  margin-bottom: var(--sp-3, 12px);
}
.ops-page-section__header h2 {
  margin: 0;
  font-size: var(--fs-h3, 1.25rem);
}
```

- [ ] **Step 5: Run — expect PASS**

Expected: tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/pages/ops
git commit -m "feat(ops): add 'Surfaces em execução' section with IntegrationSurfaceSlot"
```

---

## Task 6: Integrate into OverviewPage

**Files:**
- Modify: `src/pages/OverviewPage.tsx`
- Modify: `src/pages/OverviewPage.test.tsx`

- [ ] **Step 1: Failing test**

Append to `src/pages/OverviewPage.test.tsx`:

```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { OverviewPage } from "./OverviewPage";

// Reuse existing mock setup; add fetchIntegrationSurfaces
vi.mock("../lib/api", async (orig) => {
  const real = await (orig as () => Promise<unknown>)();
  return {
    ...(real as object),
    fetchIntegrationSurfaces: vi.fn().mockResolvedValue({
      items: [
        {
          id: "h",
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
    })
  };
});

function setup() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <OverviewPage canSeeOps={true} />
      </QueryClientProvider>
    </MemoryRouter>
  );
}

describe("OverviewPage with console-home slot", () => {
  it("renders Atalhos section", async () => {
    setup();
    await waitFor(() => expect(screen.getByText(/Atalhos/i)).toBeInTheDocument());
  });

  it("renders surface card from console-home", async () => {
    setup();
    await waitFor(() => expect(screen.getByText("Pinned")).toBeInTheDocument());
  });
});
```

- [ ] **Step 2: Modify OverviewPage**

In `src/pages/OverviewPage.tsx`, add import:

```tsx
import { IntegrationSurfaceSlot } from "../lib/integration-surfaces";
```

Add a section ABOVE the existing `home-grid` (or wherever makes most visual sense — right after the welcome hero):

```tsx
<section className="home-shortcuts" aria-label="Atalhos">
  <header className="home-shortcuts__header">
    <h2>Atalhos</h2>
  </header>
  <IntegrationSurfaceSlot slot="console-home" layout="grid" />
</section>
```

Add to `OverviewPage.css`:

```css
.home-shortcuts {
  margin: var(--sp-5, 24px) 0;
}
.home-shortcuts__header h2 {
  margin: 0 0 var(--sp-3, 12px) 0;
  font-size: var(--fs-h3, 1.25rem);
}
```

- [ ] **Step 3: Run — expect PASS**

Expected: tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/pages/OverviewPage.tsx src/pages/OverviewPage.test.tsx src/pages/OverviewPage.css
git commit -m "feat(home): render console-home SurfaceSlot under 'Atalhos'"
```

---

## Task 7: Integrate into CollaboratorDetailPage

**Files:**
- Modify: `src/pages/collaborators/CollaboratorDetailPage.tsx`
- Modify: `src/pages/collaborators/CollaboratorDetailPage.test.tsx` (or add)

- [ ] **Step 1: Failing test**

Add to `src/pages/collaborators/CollaboratorDetailPage.test.tsx`:

```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { CollaboratorDetailPage } from "./CollaboratorDetailPage";

vi.mock("../../lib/api", async (orig) => {
  const real = await (orig as () => Promise<unknown>)();
  return {
    ...(real as object),
    fetchIntegrationSurfaces: vi.fn().mockResolvedValue({
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
    })
  };
});

function setup() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={["/collaborators/abc"]}>
      <QueryClientProvider client={qc}>
        <Routes>
          <Route path="/collaborators/:id" element={<CollaboratorDetailPage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>
  );
}

describe("CollaboratorDetailPage with colaborador-detail slot", () => {
  it("renders 'Sistemas vinculados' section", async () => {
    setup();
    await waitFor(() =>
      expect(screen.getByText(/Sistemas vinculados/i)).toBeInTheDocument()
    );
  });

  it("renders linked surface card", async () => {
    setup();
    await waitFor(() => expect(screen.getByText("Grafana")).toBeInTheDocument());
  });
});
```

- [ ] **Step 2: Modify CollaboratorDetailPage**

In `src/pages/collaborators/CollaboratorDetailPage.tsx`, add the import:

```tsx
import { IntegrationSurfaceSlot } from "../../lib/integration-surfaces";
```

Add a section AFTER the existing detail-grid (inside the "happy path" branch — when collaborator loaded successfully):

```tsx
<section className="detail-linked-systems" aria-label="Sistemas vinculados">
  <header className="detail-linked-systems__header">
    <h2>Sistemas vinculados</h2>
  </header>
  <IntegrationSurfaceSlot slot="colaborador-detail" layout="inline" />
</section>
```

Add to `CollaboratorDetailPage.css`:

```css
.detail-linked-systems {
  margin-top: var(--sp-5, 24px);
}
.detail-linked-systems__header h2 {
  margin: 0 0 var(--sp-3, 12px) 0;
  font-size: var(--fs-h3, 1.25rem);
}
```

- [ ] **Step 3: Run — expect PASS**

Expected: tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/pages/collaborators
git commit -m "feat(colaborador): add 'Sistemas vinculados' section with colaborador-detail slot"
```

---

## Task 8: Build + smoke

**Files:** none

- [ ] **Step 1: Run full test suite**

```bash
cd /Users/dakasa/projects/yggdrasil/surface-console
npm run test:run
```

Expected: all existing + new tests PASS.

- [ ] **Step 2: Build**

```bash
npm run build
```

Expected: clean (`tsc --noEmit -p tsconfig.app.json` + `vite build` succeed).

- [ ] **Step 3: Dev server visual smoke (optional, manual)**

```bash
npm run dev
```

Visit in browser (with valid session cookie):
- `/ops/integrations` — should show new "Surfaces em execução" section (empty state until Phase 0b deployed)
- `/` — should show "Atalhos" section (empty state)
- `/collaborators/<any-uuid>` — should show "Sistemas vinculados" (empty state)

- [ ] **Step 4: Tag sync gate**

```bash
git commit --allow-empty -m "chore: Phase 0c complete — IntegrationSurfaceSlot integrated in 3 pages"
```

---

## Phase 0c sync gate (after Task 8)

1. ✅ Module `src/lib/integration-surfaces/` published (types, hook, card, slot, CSS)
2. ✅ Existing `src/lib/surfaces/` untouched (vestigial; safe coexistence)
3. ✅ `fetchIntegrationSurfaces` added to `src/lib/api.ts`
4. ✅ Three pages render new sections via `IntegrationSurfaceSlot`
5. ✅ All vitest tests pass; build clean
6. ✅ Page props preserved (`canSeeOps`, `userName`)

---

## Final code reviewer dispatch (after Task 8)

Reviewer checks:
- No `@mui/material` imports anywhere in new files
- All CSS uses `var(--token-*)` fallbacks; no hardcoded hex colors except brand-specific badges
- `useQuery` everywhere; no homegrown caching
- `<a href>` for navigation with `e.preventDefault()` when `onClick` provided — never `window.location.assign()` (the `<a href>` is more accessible: middle-click, keyboard, screen readers)
- Tests mock `../api` (or `../../lib/api`) at module level; no hand-rolled fetch mocks at hook level
- Page props `canSeeOps` / `userName` preserved in `OpsIntegrationsPage` and `OverviewPage`
- Route is `/collaborators/:id` (English; the spec earlier said `/colaboradores/` — that was wrong, actual is English)
- No imports from `src/lib/surfaces/` (the old vestigial module) — naming separation respected
- `staleTime: 5 * 60_000` matches spec §5.5 cache budget

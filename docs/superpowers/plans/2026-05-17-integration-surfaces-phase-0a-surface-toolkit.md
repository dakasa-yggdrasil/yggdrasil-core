# Integration Surfaces — Phase 0a: surface-toolkit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `@yggdrasil/surface-toolkit@0.1.0` — a published npm package providing the shared design system, hooks, and `IntegrationAdminShell` consumed by all integration surfaces (Phase 1).

**Architecture:** Vite library mode build (ESM + CJS + .d.ts), React 19 + TypeScript, vitest for unit tests, peer dependencies on react, react-dom, react-router-dom v7, @tanstack/react-query v5, @mui/material v6. New repo `dakasa-yggdrasil/surface-toolkit`. Auto-publish to npm + GHCR npm via GitHub Actions on tag push.

**Tech Stack:** TypeScript 5.x, React 19, Vite 5 (library mode), vitest, @testing-library/react, @mui/material 6 (peer), @tanstack/react-query 5 (peer), react-router-dom 7 (peer).

**Spec reference:** `/Users/dakasa/projects/yggdrasil/yggdrasil-core/docs/superpowers/specs/2026-05-17-integration-surfaces-design.md` §6.

**Working directory:** `/Users/dakasa/projects/yggdrasil/surface-toolkit/` (create at task 1).

---

## Task 1: Bootstrap repo

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/package.json`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/tsconfig.json`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/vite.config.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/vitest.config.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/.gitignore`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/index.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/test-setup.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/README.md`

- [ ] **Step 1: Create directory and initialize git**

```bash
mkdir -p /Users/dakasa/projects/yggdrasil/surface-toolkit
cd /Users/dakasa/projects/yggdrasil/surface-toolkit
git init
git checkout -b main
```

- [ ] **Step 2: Write package.json**

```json
{
  "name": "@yggdrasil/surface-toolkit",
  "version": "0.1.0",
  "private": false,
  "type": "module",
  "description": "Shared design system, hooks, and shells for Yggdrasil integration surfaces",
  "main": "./dist/index.cjs",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.js",
      "require": "./dist/index.cjs"
    },
    "./styles": "./dist/styles.css"
  },
  "files": ["dist", "README.md", "LICENSE"],
  "scripts": {
    "build": "vite build && tsc --emitDeclarationOnly --declaration --outDir dist",
    "test": "vitest run",
    "test:watch": "vitest",
    "lint": "tsc --noEmit"
  },
  "peerDependencies": {
    "react": "^19.0.0",
    "react-dom": "^19.0.0",
    "react-router-dom": "^7.0.0",
    "@tanstack/react-query": "^5.0.0",
    "@mui/material": "^6.0.0",
    "@emotion/react": "^11.0.0",
    "@emotion/styled": "^11.0.0"
  },
  "devDependencies": {
    "@testing-library/jest-dom": "^6.4.0",
    "@testing-library/react": "^16.0.0",
    "@testing-library/user-event": "^14.5.0",
    "@types/react": "^19.0.0",
    "@types/react-dom": "^19.0.0",
    "@vitejs/plugin-react": "^4.3.0",
    "jsdom": "^25.0.0",
    "react": "^19.0.0",
    "react-dom": "^19.0.0",
    "react-router-dom": "^7.0.0",
    "@tanstack/react-query": "^5.0.0",
    "@mui/material": "^6.0.0",
    "@emotion/react": "^11.0.0",
    "@emotion/styled": "^11.0.0",
    "typescript": "^5.5.0",
    "vite": "^5.4.0",
    "vite-plugin-dts": "^4.0.0",
    "vitest": "^2.0.0"
  },
  "publishConfig": { "access": "public" },
  "repository": { "type": "git", "url": "git+https://github.com/dakasa-yggdrasil/surface-toolkit.git" },
  "license": "Apache-2.0"
}
```

- [ ] **Step 3: Write tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "isolatedModules": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "declarationMap": true,
    "outDir": "dist",
    "types": ["vitest/globals", "@testing-library/jest-dom"]
  },
  "include": ["src"],
  "exclude": ["dist", "node_modules", "**/*.test.ts", "**/*.test.tsx"]
}
```

- [ ] **Step 4: Write vite.config.ts**

```ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";

export default defineConfig({
  plugins: [react()],
  build: {
    lib: {
      entry: resolve(__dirname, "src/index.ts"),
      name: "YggdrasilSurfaceToolkit",
      formats: ["es", "cjs"],
      fileName: (format) => `index.${format === "es" ? "js" : "cjs"}`
    },
    rollupOptions: {
      external: [
        "react",
        "react-dom",
        "react/jsx-runtime",
        "react-router-dom",
        "@tanstack/react-query",
        "@mui/material",
        "@emotion/react",
        "@emotion/styled"
      ]
    },
    sourcemap: true
  }
});
```

- [ ] **Step 5: Write vitest.config.ts**

```ts
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
    css: false
  }
});
```

- [ ] **Step 6: Write src/test-setup.ts**

```ts
import "@testing-library/jest-dom/vitest";
```

- [ ] **Step 7: Write src/index.ts (empty entry point)**

```ts
// All public exports re-exported from here as components/hooks/etc are added.
export {};
```

- [ ] **Step 8: Write .gitignore**

```
node_modules/
dist/
*.log
.DS_Store
coverage/
```

- [ ] **Step 9: Write README.md**

```markdown
# @yggdrasil/surface-toolkit

Shared design system, hooks, and `IntegrationAdminShell` consumed by Yggdrasil integration surfaces.

See `docs/superpowers/specs/2026-05-17-integration-surfaces-design.md` in `yggdrasil-core` for spec.

## Install

\`\`\`bash
npm install @yggdrasil/surface-toolkit
\`\`\`

## License

Apache-2.0
```

- [ ] **Step 10: Install + verify baseline**

```bash
npm install
npm test
```

Expected: `npm install` succeeds; `npm test` reports "No test files found, exiting with code 0" or similar (zero tests yet).

- [ ] **Step 11: Commit**

```bash
git add .
git commit -m "feat: bootstrap surface-toolkit (vite lib + ts + vitest)"
```

---

## Task 2: Design tokens

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/tokens/colors.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/tokens/spacing.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/tokens/typography.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/tokens/brand.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/tokens/index.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/tokens/tokens.test.ts`

- [ ] **Step 1: Write the failing test**

`src/tokens/tokens.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { tokens } from "./index";

describe("tokens", () => {
  it("exposes colors palette", () => {
    expect(tokens.colors.text.primary).toBeTypeOf("string");
    expect(tokens.colors.background.default).toBeTypeOf("string");
    expect(tokens.colors.semantic.error).toBeTypeOf("string");
    expect(tokens.colors.semantic.success).toBeTypeOf("string");
  });

  it("exposes spacing scale", () => {
    expect(tokens.spacing.xs).toBe(4);
    expect(tokens.spacing.sm).toBe(8);
    expect(tokens.spacing.md).toBe(16);
    expect(tokens.spacing.lg).toBe(24);
    expect(tokens.spacing.xl).toBe(32);
  });

  it("exposes typography", () => {
    expect(tokens.typography.heading.h1.fontSize).toBeTypeOf("string");
    expect(tokens.typography.body.fontSize).toBeTypeOf("string");
  });

  it("exposes brand tokens for known integrations", () => {
    expect(tokens.brand.slack.primary).toBe("#4A154B");
    expect(tokens.brand.github.primary).toBe("#24292F");
    expect(tokens.brand.grafana.primary).toBe("#F46800");
    expect(tokens.brand["google-workspace"].primary).toBe("#4285F4");
    expect(tokens.brand.kubernetes.primary).toBe("#326CE5");
    expect(tokens.brand.aws.primary).toBe("#FF9900");
    expect(tokens.brand["secrets-management"].primary).toBe("#5C6BC0");
    expect(tokens.brand["webhooks-external"].primary).toBe("#00ACC1");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- tokens.test.ts`
Expected: FAIL — "Cannot find module './index'" or "tokens is not defined".

- [ ] **Step 3: Implement src/tokens/colors.ts**

```ts
export const colors = {
  text: {
    primary: "#0F172A",
    secondary: "#475569",
    inverse: "#F8FAFC",
    disabled: "#94A3B8"
  },
  background: {
    default: "#FFFFFF",
    paper: "#F8FAFC",
    elevated: "#FFFFFF"
  },
  semantic: {
    error: "#DC2626",
    warning: "#F59E0B",
    success: "#16A34A",
    info: "#2563EB"
  },
  divider: "#E2E8F0"
} as const;
```

- [ ] **Step 4: Implement src/tokens/spacing.ts**

```ts
export const spacing = {
  xs: 4,
  sm: 8,
  md: 16,
  lg: 24,
  xl: 32,
  "2xl": 48,
  "3xl": 64
} as const;
```

- [ ] **Step 5: Implement src/tokens/typography.ts**

```ts
export const typography = {
  fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  heading: {
    h1: { fontSize: "2rem", fontWeight: 700, lineHeight: 1.2 },
    h2: { fontSize: "1.5rem", fontWeight: 700, lineHeight: 1.25 },
    h3: { fontSize: "1.25rem", fontWeight: 600, lineHeight: 1.3 },
    h4: { fontSize: "1.125rem", fontWeight: 600, lineHeight: 1.4 }
  },
  body: { fontSize: "0.9375rem", fontWeight: 400, lineHeight: 1.6 },
  caption: { fontSize: "0.8125rem", fontWeight: 400, lineHeight: 1.5 },
  mono: 'ui-monospace, "SF Mono", Monaco, "Cascadia Code", "Roboto Mono", monospace'
} as const;
```

- [ ] **Step 6: Implement src/tokens/brand.ts**

```ts
export const brand = {
  slack: { primary: "#4A154B", onPrimary: "#FFFFFF" },
  github: { primary: "#24292F", onPrimary: "#FFFFFF" },
  grafana: { primary: "#F46800", onPrimary: "#FFFFFF" },
  "google-workspace": { primary: "#4285F4", onPrimary: "#FFFFFF" },
  kubernetes: { primary: "#326CE5", onPrimary: "#FFFFFF" },
  aws: { primary: "#FF9900", onPrimary: "#0F172A" },
  "secrets-management": { primary: "#5C6BC0", onPrimary: "#FFFFFF" },
  "webhooks-external": { primary: "#00ACC1", onPrimary: "#FFFFFF" }
} as const;

export type BrandKey = keyof typeof brand;
```

- [ ] **Step 7: Implement src/tokens/index.ts**

```ts
import { colors } from "./colors";
import { spacing } from "./spacing";
import { typography } from "./typography";
import { brand } from "./brand";

export const tokens = { colors, spacing, typography, brand } as const;

export type Tokens = typeof tokens;
export { colors, spacing, typography, brand };
export type { BrandKey } from "./brand";
```

- [ ] **Step 8: Wire export in src/index.ts**

Replace `src/index.ts` content with:

```ts
export * from "./tokens";
```

- [ ] **Step 9: Run test to verify it passes**

Run: `npm test -- tokens.test.ts`
Expected: PASS — 4 tests passing.

- [ ] **Step 10: Commit**

```bash
git add src/tokens src/index.ts
git commit -m "feat(tokens): colors, spacing, typography, brand palette"
```

---

## Task 3: Icon system

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/icons/IntegrationIcon.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/icons/index.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/icons/IntegrationIcon.test.tsx`

- [ ] **Step 1: Write the failing test**

`src/icons/IntegrationIcon.test.tsx`:

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { IntegrationIcon } from "./IntegrationIcon";

describe("IntegrationIcon", () => {
  it("renders icon by name", () => {
    render(<IntegrationIcon name="slack" data-testid="icon" />);
    const el = screen.getByTestId("icon");
    expect(el).toBeInTheDocument();
    expect(el).toHaveAttribute("aria-label", "slack");
  });

  it("falls back to generic placeholder for unknown name", () => {
    render(<IntegrationIcon name="unknown-xyz" data-testid="icon" />);
    const el = screen.getByTestId("icon");
    expect(el).toBeInTheDocument();
    expect(el).toHaveAttribute("aria-label", "unknown-xyz");
  });
});
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `npm test -- IntegrationIcon.test.tsx`
Expected: FAIL — "Cannot find module './IntegrationIcon'".

- [ ] **Step 3: Implement src/icons/IntegrationIcon.tsx**

```tsx
import type { CSSProperties } from "react";
import { brand, type BrandKey } from "../tokens/brand";

export interface IntegrationIconProps {
  name: string;
  size?: number;
  "data-testid"?: string;
}

// Minimal initial-based glyph; surfaces can ship their own SVG later via display.icon=svg-url
export function IntegrationIcon({ name, size = 24, ...rest }: IntegrationIconProps) {
  const brandKey = name as BrandKey;
  const palette = brand[brandKey] ?? { primary: "#475569", onPrimary: "#FFFFFF" };
  const initial = name.charAt(0).toUpperCase();
  const style: CSSProperties = {
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    width: size,
    height: size,
    borderRadius: size * 0.2,
    background: palette.primary,
    color: palette.onPrimary,
    fontWeight: 600,
    fontSize: size * 0.5,
    fontFamily: "system-ui, sans-serif",
    lineHeight: 1
  };
  return (
    <span
      role="img"
      aria-label={name}
      style={style}
      data-testid={rest["data-testid"]}
    >
      {initial}
    </span>
  );
}
```

- [ ] **Step 4: Implement src/icons/index.ts**

```ts
export { IntegrationIcon } from "./IntegrationIcon";
export type { IntegrationIconProps } from "./IntegrationIcon";
```

- [ ] **Step 5: Wire export in src/index.ts**

Append to `src/index.ts`:

```ts
export * from "./icons";
```

- [ ] **Step 6: Run test — expect PASS**

Run: `npm test -- IntegrationIcon.test.tsx`
Expected: PASS — 2 tests passing.

- [ ] **Step 7: Commit**

```bash
git add src/icons src/index.ts
git commit -m "feat(icons): IntegrationIcon with brand-aware fallback"
```

---

## Task 4: LoadingState, EmptyState, ErrorBoundary

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/components/LoadingState.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/components/EmptyState.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/components/ErrorBoundary.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/components/states.test.tsx`

- [ ] **Step 1: Write the failing test**

`src/components/states.test.tsx`:

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { LoadingState } from "./LoadingState";
import { EmptyState } from "./EmptyState";
import { ErrorBoundary } from "./ErrorBoundary";

describe("LoadingState", () => {
  it("renders default label", () => {
    render(<LoadingState />);
    expect(screen.getByRole("status")).toHaveTextContent(/carregando/i);
  });

  it("renders custom label", () => {
    render(<LoadingState label="Buscando" />);
    expect(screen.getByRole("status")).toHaveTextContent("Buscando");
  });
});

describe("EmptyState", () => {
  it("renders title and description", () => {
    render(<EmptyState title="Nada aqui" description="Tente recarregar" />);
    expect(screen.getByText("Nada aqui")).toBeInTheDocument();
    expect(screen.getByText("Tente recarregar")).toBeInTheDocument();
  });
});

describe("ErrorBoundary", () => {
  it("renders fallback when child throws", () => {
    function Bad(): never {
      throw new Error("boom");
    }
    // ErrorBoundary catches; suppress React's error logging for this test
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    render(
      <ErrorBoundary>
        <Bad />
      </ErrorBoundary>
    );
    expect(screen.getByText(/erro/i)).toBeInTheDocument();
    spy.mockRestore();
  });

  it("renders children when no error", () => {
    render(
      <ErrorBoundary>
        <div>OK</div>
      </ErrorBoundary>
    );
    expect(screen.getByText("OK")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `npm test -- states.test.tsx`
Expected: FAIL — modules not found.

- [ ] **Step 3: Implement LoadingState**

`src/components/LoadingState.tsx`:

```tsx
import { CircularProgress, Stack, Typography } from "@mui/material";
import { spacing } from "../tokens/spacing";

export interface LoadingStateProps {
  label?: string;
  size?: number;
}

export function LoadingState({ label = "Carregando…", size = 32 }: LoadingStateProps) {
  return (
    <Stack
      role="status"
      alignItems="center"
      justifyContent="center"
      spacing={1}
      sx={{ p: `${spacing.lg}px` }}
    >
      <CircularProgress size={size} />
      <Typography variant="body2" color="text.secondary">
        {label}
      </Typography>
    </Stack>
  );
}
```

- [ ] **Step 4: Implement EmptyState**

`src/components/EmptyState.tsx`:

```tsx
import type { ReactNode } from "react";
import { Stack, Typography, Box } from "@mui/material";
import { spacing } from "../tokens/spacing";

export interface EmptyStateProps {
  title: string;
  description?: string;
  icon?: ReactNode;
  action?: ReactNode;
}

export function EmptyState({ title, description, icon, action }: EmptyStateProps) {
  return (
    <Stack
      alignItems="center"
      justifyContent="center"
      spacing={1}
      sx={{ p: `${spacing.xl}px`, textAlign: "center" }}
    >
      {icon ? <Box sx={{ color: "text.secondary" }}>{icon}</Box> : null}
      <Typography variant="h6">{title}</Typography>
      {description ? (
        <Typography variant="body2" color="text.secondary">
          {description}
        </Typography>
      ) : null}
      {action}
    </Stack>
  );
}
```

- [ ] **Step 5: Implement ErrorBoundary**

`src/components/ErrorBoundary.tsx`:

```tsx
import { Component, type ErrorInfo, type ReactNode } from "react";
import { Alert, AlertTitle, Box } from "@mui/material";

interface Props {
  children: ReactNode;
  fallback?: (error: Error, reset: () => void) => ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // eslint-disable-next-line no-console
    console.error("ErrorBoundary caught:", error, info);
  }

  reset = () => this.setState({ error: null });

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    if (this.props.fallback) return this.props.fallback(error, this.reset);
    return (
      <Box sx={{ p: 2 }}>
        <Alert severity="error">
          <AlertTitle>Erro inesperado</AlertTitle>
          {error.message}
        </Alert>
      </Box>
    );
  }
}
```

- [ ] **Step 6: Wire exports**

Create `src/components/index.ts`:

```ts
export { LoadingState } from "./LoadingState";
export type { LoadingStateProps } from "./LoadingState";
export { EmptyState } from "./EmptyState";
export type { EmptyStateProps } from "./EmptyState";
export { ErrorBoundary } from "./ErrorBoundary";
```

Append to `src/index.ts`:

```ts
export * from "./components";
```

- [ ] **Step 7: Run test — expect PASS**

Run: `npm test -- states.test.tsx`
Expected: PASS — 6 tests passing.

- [ ] **Step 8: Commit**

```bash
git add src/components src/index.ts
git commit -m "feat(components): LoadingState, EmptyState, ErrorBoundary"
```

---

## Task 5: PageHeader + Tabs

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/components/PageHeader.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/components/Tabs.tsx`
- Modify: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/components/index.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/components/PageHeader.test.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/components/Tabs.test.tsx`

- [ ] **Step 1: Write PageHeader failing test**

`src/components/PageHeader.test.tsx`:

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { PageHeader } from "./PageHeader";

describe("PageHeader", () => {
  it("renders title", () => {
    render(<PageHeader title="Slack" />);
    expect(screen.getByRole("heading", { name: "Slack" })).toBeInTheDocument();
  });

  it("renders subtitle when provided", () => {
    render(<PageHeader title="Slack" subtitle="Workspace & vínculos" />);
    expect(screen.getByText("Workspace & vínculos")).toBeInTheDocument();
  });

  it("renders breadcrumb items", () => {
    render(<PageHeader title="Slack" breadcrumb={[{ label: "Integrações", to: "/ops/integrations" }, { label: "Slack" }]} />);
    expect(screen.getByText("Integrações")).toBeInTheDocument();
    expect(screen.getAllByText("Slack")[0]).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run — expect FAIL**

Run: `npm test -- PageHeader.test.tsx`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement PageHeader.tsx**

```tsx
import type { ReactNode } from "react";
import { Stack, Typography, Breadcrumbs, Link as MuiLink, Box } from "@mui/material";
import { Link as RouterLink } from "react-router-dom";
import { spacing } from "../tokens/spacing";

export interface BreadcrumbItem {
  label: string;
  to?: string;
}

export interface PageHeaderProps {
  title: string;
  subtitle?: string;
  breadcrumb?: BreadcrumbItem[];
  actions?: ReactNode;
}

export function PageHeader({ title, subtitle, breadcrumb, actions }: PageHeaderProps) {
  return (
    <Box sx={{ pb: `${spacing.md}px`, borderBottom: 1, borderColor: "divider", mb: `${spacing.lg}px` }}>
      {breadcrumb && breadcrumb.length > 0 ? (
        <Breadcrumbs aria-label="breadcrumb" sx={{ mb: 1 }}>
          {breadcrumb.map((item, idx) => {
            const last = idx === breadcrumb.length - 1;
            if (last || !item.to) {
              return (
                <Typography key={idx} color="text.primary" variant="body2">
                  {item.label}
                </Typography>
              );
            }
            return (
              <MuiLink key={idx} component={RouterLink} to={item.to} variant="body2" underline="hover">
                {item.label}
              </MuiLink>
            );
          })}
        </Breadcrumbs>
      ) : null}
      <Stack direction="row" alignItems="flex-start" justifyContent="space-between" spacing={2}>
        <Box>
          <Typography variant="h4" component="h1">
            {title}
          </Typography>
          {subtitle ? (
            <Typography variant="body1" color="text.secondary">
              {subtitle}
            </Typography>
          ) : null}
        </Box>
        {actions}
      </Stack>
    </Box>
  );
}
```

- [ ] **Step 4: Run PageHeader test — expect PASS (need to wrap in router)**

Need `MemoryRouter` wrapper. Update test:

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { PageHeader } from "./PageHeader";

function renderWithRouter(ui: React.ReactNode) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

describe("PageHeader", () => {
  it("renders title", () => {
    renderWithRouter(<PageHeader title="Slack" />);
    expect(screen.getByRole("heading", { name: "Slack" })).toBeInTheDocument();
  });

  it("renders subtitle when provided", () => {
    renderWithRouter(<PageHeader title="Slack" subtitle="Workspace & vínculos" />);
    expect(screen.getByText("Workspace & vínculos")).toBeInTheDocument();
  });

  it("renders breadcrumb items", () => {
    renderWithRouter(
      <PageHeader title="Slack" breadcrumb={[{ label: "Integrações", to: "/ops/integrations" }, { label: "Slack" }]} />
    );
    expect(screen.getByText("Integrações")).toBeInTheDocument();
    expect(screen.getAllByText("Slack").length).toBeGreaterThan(0);
  });
});
```

Run: `npm test -- PageHeader.test.tsx`
Expected: PASS — 3 tests.

- [ ] **Step 5: Write Tabs failing test**

`src/components/Tabs.test.tsx`:

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { Tabs, TabPanel } from "./Tabs";

const defs = [
  { id: "overview", label: "Overview" },
  { id: "drift", label: "Drift" },
  { id: "identities", label: "Identidades" }
];

function Harness() {
  return (
    <MemoryRouter initialEntries={["/parent/overview"]}>
      <Routes>
        <Route
          path="/parent/:tabId"
          element={
            <>
              <Tabs items={defs} basePath="/parent" />
              <TabPanel id="overview">
                <div>Overview content</div>
              </TabPanel>
              <TabPanel id="drift">
                <div>Drift content</div>
              </TabPanel>
              <TabPanel id="identities">
                <div>Identities content</div>
              </TabPanel>
            </>
          }
        />
      </Routes>
    </MemoryRouter>
  );
}

describe("Tabs", () => {
  it("renders all tab labels", () => {
    render(<Harness />);
    expect(screen.getByRole("tab", { name: "Overview" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Drift" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Identidades" })).toBeInTheDocument();
  });

  it("shows panel for selected tab", () => {
    render(<Harness />);
    expect(screen.getByText("Overview content")).toBeInTheDocument();
    expect(screen.queryByText("Drift content")).not.toBeInTheDocument();
  });

  it("switches panels when a tab is clicked", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole("tab", { name: "Drift" }));
    expect(screen.getByText("Drift content")).toBeInTheDocument();
  });
});
```

- [ ] **Step 6: Run — expect FAIL**

Run: `npm test -- Tabs.test.tsx`
Expected: FAIL.

- [ ] **Step 7: Implement Tabs.tsx**

```tsx
import { createContext, useContext, type ReactNode } from "react";
import { Tabs as MuiTabs, Tab } from "@mui/material";
import { useParams, useNavigate, useMatch } from "react-router-dom";

export interface TabDef {
  id: string;
  label: string;
}

interface TabsCtx {
  activeId: string;
}
const TabsContext = createContext<TabsCtx>({ activeId: "" });

export interface TabsProps {
  items: TabDef[];
  basePath: string; // e.g., "/parent"
}

export function Tabs({ items, basePath }: TabsProps) {
  const params = useParams<{ tabId: string }>();
  const navigate = useNavigate();
  const matchedBase = useMatch(`${basePath}/*`);
  const activeId = params.tabId ?? items[0]?.id ?? "";

  if (!matchedBase) return null;

  const handleChange = (_: unknown, value: string) => {
    navigate(`${basePath}/${value}`);
  };

  return (
    <TabsContext.Provider value={{ activeId }}>
      <MuiTabs value={activeId} onChange={handleChange} aria-label="surface tabs">
        {items.map((t) => (
          <Tab key={t.id} value={t.id} label={t.label} />
        ))}
      </MuiTabs>
    </TabsContext.Provider>
  );
}

export interface TabPanelProps {
  id: string;
  children: ReactNode;
}

export function TabPanel({ id, children }: TabPanelProps) {
  const { activeId } = useContext(TabsContext);
  if (activeId !== id) return null;
  return (
    <div role="tabpanel" id={`panel-${id}`}>
      {children}
    </div>
  );
}
```

- [ ] **Step 8: Run — expect PASS**

Run: `npm test -- Tabs.test.tsx`
Expected: PASS — 3 tests.

- [ ] **Step 9: Wire exports**

Append to `src/components/index.ts`:

```ts
export { PageHeader } from "./PageHeader";
export type { PageHeaderProps, BreadcrumbItem } from "./PageHeader";
export { Tabs, TabPanel } from "./Tabs";
export type { TabDef, TabsProps, TabPanelProps } from "./Tabs";
```

- [ ] **Step 10: Commit**

```bash
git add src/components
git commit -m "feat(components): PageHeader + Tabs with router-driven selection"
```

---

## Task 6: DataTable

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/components/DataTable.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/components/DataTable.test.tsx`

- [ ] **Step 1: Write failing test**

`src/components/DataTable.test.tsx`:

```tsx
import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DataTable } from "./DataTable";

interface Row {
  id: string;
  name: string;
  email: string;
  count: number;
}

const rows: Row[] = [
  { id: "1", name: "Alice", email: "alice@x", count: 10 },
  { id: "2", name: "Bob", email: "bob@x", count: 3 },
  { id: "3", name: "Carol", email: "carol@x", count: 7 }
];

describe("DataTable", () => {
  it("renders columns and rows", () => {
    render(
      <DataTable<Row>
        rows={rows}
        keyField="id"
        columns={[
          { id: "name", header: "Nome", accessor: (r) => r.name },
          { id: "email", header: "Email", accessor: (r) => r.email }
        ]}
      />
    );
    expect(screen.getByText("Nome")).toBeInTheDocument();
    expect(screen.getByText("Alice")).toBeInTheDocument();
    expect(screen.getByText("Bob")).toBeInTheDocument();
    expect(screen.getByText("Carol")).toBeInTheDocument();
  });

  it("paginates when more rows than pageSize", () => {
    const many: Row[] = Array.from({ length: 25 }, (_, i) => ({
      id: String(i),
      name: `User${i}`,
      email: `${i}@x`,
      count: i
    }));
    render(
      <DataTable<Row>
        rows={many}
        keyField="id"
        pageSize={10}
        columns={[{ id: "name", header: "Nome", accessor: (r) => r.name }]}
      />
    );
    expect(screen.getByText("User0")).toBeInTheDocument();
    expect(screen.queryByText("User10")).not.toBeInTheDocument();
  });

  it("renders empty state when rows is empty", () => {
    render(
      <DataTable<Row>
        rows={[]}
        keyField="id"
        columns={[{ id: "name", header: "Nome", accessor: (r) => r.name }]}
        emptyLabel="Nenhum dado"
      />
    );
    expect(screen.getByText("Nenhum dado")).toBeInTheDocument();
  });

  it("sorts by column when sortable header clicked", async () => {
    const user = userEvent.setup();
    render(
      <DataTable<Row>
        rows={rows}
        keyField="id"
        columns={[
          { id: "name", header: "Nome", accessor: (r) => r.name, sortable: true },
          { id: "count", header: "Count", accessor: (r) => r.count, sortable: true }
        ]}
      />
    );
    await user.click(screen.getByRole("button", { name: /count/i }));
    const tbody = screen.getByRole("table").querySelector("tbody")!;
    const firstName = within(tbody).getAllByRole("row")[0].textContent;
    expect(firstName).toContain("Bob");
  });
});
```

- [ ] **Step 2: Run — expect FAIL**

Run: `npm test -- DataTable.test.tsx`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement DataTable.tsx**

```tsx
import { useMemo, useState } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Paper,
  TableSortLabel
} from "@mui/material";
import { EmptyState } from "./EmptyState";

export interface ColumnDef<T> {
  id: string;
  header: string;
  accessor: (row: T) => unknown;
  sortable?: boolean;
}

export interface DataTableProps<T> {
  rows: T[];
  columns: ColumnDef<T>[];
  keyField: keyof T;
  pageSize?: number;
  emptyLabel?: string;
}

type Order = "asc" | "desc";

export function DataTable<T>({ rows, columns, keyField, pageSize = 25, emptyLabel = "Nenhum registro" }: DataTableProps<T>) {
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(pageSize);
  const [sortBy, setSortBy] = useState<string | null>(null);
  const [order, setOrder] = useState<Order>("asc");

  const sorted = useMemo(() => {
    if (!sortBy) return rows;
    const col = columns.find((c) => c.id === sortBy);
    if (!col) return rows;
    const copy = [...rows];
    copy.sort((a, b) => {
      const av = col.accessor(a) as never;
      const bv = col.accessor(b) as never;
      if (av < bv) return order === "asc" ? -1 : 1;
      if (av > bv) return order === "asc" ? 1 : -1;
      return 0;
    });
    return copy;
  }, [rows, columns, sortBy, order]);

  const paged = sorted.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage);

  if (rows.length === 0) {
    return <EmptyState title={emptyLabel} />;
  }

  return (
    <TableContainer component={Paper} variant="outlined">
      <Table size="small">
        <TableHead>
          <TableRow>
            {columns.map((c) => (
              <TableCell key={c.id}>
                {c.sortable ? (
                  <TableSortLabel
                    active={sortBy === c.id}
                    direction={sortBy === c.id ? order : "asc"}
                    onClick={() => {
                      if (sortBy === c.id) {
                        setOrder(order === "asc" ? "desc" : "asc");
                      } else {
                        setSortBy(c.id);
                        setOrder("asc");
                      }
                    }}
                  >
                    {c.header}
                  </TableSortLabel>
                ) : (
                  c.header
                )}
              </TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>
          {paged.map((row) => (
            <TableRow key={String(row[keyField])}>
              {columns.map((c) => (
                <TableCell key={c.id}>{String(c.accessor(row) ?? "")}</TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {rows.length > rowsPerPage ? (
        <TablePagination
          component="div"
          count={rows.length}
          page={page}
          onPageChange={(_, p) => setPage(p)}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={(e) => {
            setRowsPerPage(parseInt(e.target.value, 10));
            setPage(0);
          }}
          rowsPerPageOptions={[10, 25, 50, 100]}
        />
      ) : null}
    </TableContainer>
  );
}
```

- [ ] **Step 4: Run — expect PASS**

Run: `npm test -- DataTable.test.tsx`
Expected: PASS — 4 tests.

- [ ] **Step 5: Wire export**

Append to `src/components/index.ts`:

```ts
export { DataTable } from "./DataTable";
export type { ColumnDef, DataTableProps } from "./DataTable";
```

- [ ] **Step 6: Commit**

```bash
git add src/components
git commit -m "feat(components): DataTable with sortable cols + pagination"
```

---

## Task 7: JsonViewer, TimestampRelative, HealthBadge, DriftBadge, IdentityRow

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/components/JsonViewer.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/components/TimestampRelative.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/components/HealthBadge.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/components/DriftBadge.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/components/IdentityRow.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/components/badges.test.tsx`

- [ ] **Step 1: Write failing test**

`src/components/badges.test.tsx`:

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { JsonViewer } from "./JsonViewer";
import { TimestampRelative } from "./TimestampRelative";
import { HealthBadge } from "./HealthBadge";
import { DriftBadge } from "./DriftBadge";
import { IdentityRow } from "./IdentityRow";

describe("JsonViewer", () => {
  it("renders JSON in <pre>", () => {
    render(<JsonViewer value={{ a: 1, b: "x" }} />);
    expect(screen.getByText(/"a": 1/)).toBeInTheDocument();
  });
});

describe("TimestampRelative", () => {
  it("renders 'agora' for current time", () => {
    render(<TimestampRelative isoString={new Date().toISOString()} />);
    expect(screen.getByText(/agora|segundo/i)).toBeInTheDocument();
  });

  it("renders 'há X minutos' for 5 minutes ago", () => {
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    render(<TimestampRelative isoString={fiveMinAgo} />);
    expect(screen.getByText(/há 5 minutos/)).toBeInTheDocument();
  });

  it("renders absolute date for >30 days", () => {
    const old = new Date(Date.now() - 40 * 86400000).toISOString();
    render(<TimestampRelative isoString={old} />);
    // Just check it contains a year-like token
    expect(screen.getByText(/\d{4}/)).toBeInTheDocument();
  });
});

describe("HealthBadge", () => {
  it("renders healthy", () => {
    render(<HealthBadge status="healthy" />);
    expect(screen.getByText(/saudável/i)).toBeInTheDocument();
  });
  it("renders degraded", () => {
    render(<HealthBadge status="degraded" />);
    expect(screen.getByText(/degradad/i)).toBeInTheDocument();
  });
  it("renders down", () => {
    render(<HealthBadge status="down" />);
    expect(screen.getByText(/fora/i)).toBeInTheDocument();
  });
});

describe("DriftBadge", () => {
  it("renders in-sync", () => {
    render(<DriftBadge inSync />);
    expect(screen.getByText(/sincronizad/i)).toBeInTheDocument();
  });
  it("renders out-of-sync", () => {
    render(<DriftBadge inSync={false} />);
    expect(screen.getByText(/drift/i)).toBeInTheDocument();
  });
});

describe("IdentityRow", () => {
  it("renders email and external_id", () => {
    render(
      <IdentityRow
        identity={{
          id: "abc",
          collaborator_email: "alice@dakasa.me",
          external_id: "U12345",
          external_metadata: { login: "alice" },
          status: "active",
          last_seen_at: new Date().toISOString()
        }}
      />
    );
    expect(screen.getByText("alice@dakasa.me")).toBeInTheDocument();
    expect(screen.getByText("U12345")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run — expect FAIL**

Run: `npm test -- badges.test.tsx`
Expected: FAIL — modules not found.

- [ ] **Step 3: Implement JsonViewer**

`src/components/JsonViewer.tsx`:

```tsx
import { Box } from "@mui/material";
import { typography } from "../tokens/typography";

export interface JsonViewerProps {
  value: unknown;
}

export function JsonViewer({ value }: JsonViewerProps) {
  return (
    <Box
      component="pre"
      sx={{
        m: 0,
        p: 2,
        bgcolor: "grey.50",
        border: 1,
        borderColor: "divider",
        borderRadius: 1,
        fontFamily: typography.mono,
        fontSize: "0.8125rem",
        overflow: "auto"
      }}
    >
      {JSON.stringify(value, null, 2)}
    </Box>
  );
}
```

- [ ] **Step 4: Implement TimestampRelative**

`src/components/TimestampRelative.tsx`:

```tsx
import { Tooltip } from "@mui/material";

export interface TimestampRelativeProps {
  isoString: string;
}

function format(iso: string): string {
  const target = new Date(iso).getTime();
  const now = Date.now();
  const diffSec = Math.floor((now - target) / 1000);
  if (diffSec < 5) return "agora";
  if (diffSec < 60) return `há ${diffSec} segundo${diffSec === 1 ? "" : "s"}`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `há ${diffMin} minuto${diffMin === 1 ? "" : "s"}`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `há ${diffHr} hora${diffHr === 1 ? "" : "s"}`;
  const diffD = Math.floor(diffHr / 24);
  if (diffD < 30) return `há ${diffD} dia${diffD === 1 ? "" : "s"}`;
  return new Date(iso).toLocaleDateString("pt-BR");
}

export function TimestampRelative({ isoString }: TimestampRelativeProps) {
  const absolute = new Date(isoString).toLocaleString("pt-BR");
  return (
    <Tooltip title={absolute}>
      <span>{format(isoString)}</span>
    </Tooltip>
  );
}
```

- [ ] **Step 5: Implement HealthBadge**

`src/components/HealthBadge.tsx`:

```tsx
import { Chip } from "@mui/material";

export type HealthStatus = "healthy" | "degraded" | "down" | "unknown";

export interface HealthBadgeProps {
  status: HealthStatus;
}

const map: Record<HealthStatus, { label: string; color: "success" | "warning" | "error" | "default" }> = {
  healthy: { label: "Saudável", color: "success" },
  degraded: { label: "Degradado", color: "warning" },
  down: { label: "Fora do ar", color: "error" },
  unknown: { label: "Desconhecido", color: "default" }
};

export function HealthBadge({ status }: HealthBadgeProps) {
  const { label, color } = map[status];
  return <Chip size="small" label={label} color={color} variant="outlined" />;
}
```

- [ ] **Step 6: Implement DriftBadge**

`src/components/DriftBadge.tsx`:

```tsx
import { Chip } from "@mui/material";

export interface DriftBadgeProps {
  inSync: boolean;
}

export function DriftBadge({ inSync }: DriftBadgeProps) {
  if (inSync) {
    return <Chip size="small" label="Sincronizado" color="success" />;
  }
  return <Chip size="small" label="Drift detectado" color="warning" />;
}
```

- [ ] **Step 7: Implement IdentityRow**

`src/components/IdentityRow.tsx`:

```tsx
import { Stack, Typography, Chip, Box } from "@mui/material";
import { TimestampRelative } from "./TimestampRelative";

export interface IdentityT {
  id: string;
  collaborator_email: string;
  collaborator_name?: string;
  external_id: string;
  external_metadata?: Record<string, unknown>;
  status: "active" | "soft_deleted";
  last_seen_at?: string;
}

export interface IdentityRowProps {
  identity: IdentityT;
  action?: React.ReactNode;
}

export function IdentityRow({ identity, action }: IdentityRowProps) {
  return (
    <Stack
      direction="row"
      spacing={2}
      alignItems="center"
      sx={{ py: 1, borderBottom: 1, borderColor: "divider" }}
    >
      <Box sx={{ flex: 1 }}>
        <Typography variant="body2" component="div">
          {identity.collaborator_email}
        </Typography>
        <Typography variant="caption" color="text.secondary" component="div">
          ext: {identity.external_id}
        </Typography>
      </Box>
      <Chip
        size="small"
        label={identity.status === "active" ? "Ativo" : "Desvinculado"}
        color={identity.status === "active" ? "success" : "default"}
        variant="outlined"
      />
      {identity.last_seen_at ? (
        <Typography variant="caption" color="text.secondary">
          <TimestampRelative isoString={identity.last_seen_at} />
        </Typography>
      ) : null}
      {action}
    </Stack>
  );
}
```

- [ ] **Step 8: Run — expect PASS**

Run: `npm test -- badges.test.tsx`
Expected: PASS — 9 tests.

- [ ] **Step 9: Wire exports**

Append to `src/components/index.ts`:

```ts
export { JsonViewer } from "./JsonViewer";
export type { JsonViewerProps } from "./JsonViewer";
export { TimestampRelative } from "./TimestampRelative";
export type { TimestampRelativeProps } from "./TimestampRelative";
export { HealthBadge } from "./HealthBadge";
export type { HealthBadgeProps, HealthStatus } from "./HealthBadge";
export { DriftBadge } from "./DriftBadge";
export type { DriftBadgeProps } from "./DriftBadge";
export { IdentityRow } from "./IdentityRow";
export type { IdentityRowProps, IdentityT } from "./IdentityRow";
```

- [ ] **Step 10: Commit**

```bash
git add src/components
git commit -m "feat(components): JsonViewer, TimestampRelative, HealthBadge, DriftBadge, IdentityRow"
```

---

## Task 8: useYggdrasilAPI hook

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/hooks/useYggdrasilAPI.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/hooks/useYggdrasilAPI.test.ts`

- [ ] **Step 1: Write failing test**

`src/hooks/useYggdrasilAPI.test.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import { useYggdrasilAPI } from "./useYggdrasilAPI";

describe("useYggdrasilAPI", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("returns get/post/del methods bound to default base /api/v1", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );
    const api = useYggdrasilAPI();
    const result = await api.get<{ ok: boolean }>("/integration-instances/abc");
    expect(result).toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/integration-instances/abc",
      expect.objectContaining({ credentials: "include", method: "GET" })
    );
  });

  it("respects baseUrl override", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({}), { status: 200 })
    );
    const api = useYggdrasilAPI({ baseUrl: "https://core.test/v2" });
    await api.get("/x");
    expect(fetchMock).toHaveBeenCalledWith("https://core.test/v2/x", expect.any(Object));
  });

  it("throws on non-2xx with status code in message", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ error: "nope" }), { status: 403 })
    );
    const api = useYggdrasilAPI();
    await expect(api.get("/x")).rejects.toThrow(/403/);
  });

  it("posts JSON body", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ created: true }), { status: 200 })
    );
    const api = useYggdrasilAPI();
    await api.post("/x", { a: 1 });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/x",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({ "Content-Type": "application/json" }),
        body: JSON.stringify({ a: 1 })
      })
    );
  });
});
```

- [ ] **Step 2: Run — expect FAIL**

Run: `npm test -- useYggdrasilAPI.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement useYggdrasilAPI.ts**

```ts
export interface YggdrasilAPIOptions {
  baseUrl?: string;
}

export interface YggdrasilAPI {
  get: <T>(path: string) => Promise<T>;
  post: <T>(path: string, body: unknown) => Promise<T>;
  del: <T>(path: string) => Promise<T>;
}

async function send<T>(url: string, init: RequestInit): Promise<T> {
  const resp = await fetch(url, { credentials: "include", ...init });
  if (!resp.ok) {
    let detail = "";
    try {
      detail = await resp.text();
    } catch {
      detail = "";
    }
    throw new Error(`${resp.status} ${resp.statusText}: ${detail}`);
  }
  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

export function useYggdrasilAPI(opts: YggdrasilAPIOptions = {}): YggdrasilAPI {
  const base = (opts.baseUrl ?? "/api/v1").replace(/\/$/, "");
  return {
    get: <T>(path: string) => send<T>(`${base}${path}`, { method: "GET" }),
    post: <T>(path: string, body: unknown) =>
      send<T>(`${base}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      }),
    del: <T>(path: string) => send<T>(`${base}${path}`, { method: "DELETE" })
  };
}
```

- [ ] **Step 4: Run — expect PASS**

Run: `npm test -- useYggdrasilAPI.test.ts`
Expected: PASS — 4 tests.

- [ ] **Step 5: Wire export**

Create `src/hooks/index.ts`:

```ts
export { useYggdrasilAPI } from "./useYggdrasilAPI";
export type { YggdrasilAPI, YggdrasilAPIOptions } from "./useYggdrasilAPI";
```

Append to `src/index.ts`:

```ts
export * from "./hooks";
```

- [ ] **Step 6: Commit**

```bash
git add src/hooks src/index.ts
git commit -m "feat(hooks): useYggdrasilAPI fetch wrapper with cookie auth"
```

---

## Task 9: Data hooks — useInstance, useDriftStatus, useIdentities

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/hooks/useInstance.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/hooks/useDriftStatus.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/hooks/useIdentities.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/hooks/data-hooks.test.tsx`

- [ ] **Step 1: Write failing test**

`src/hooks/data-hooks.test.tsx`:

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useInstance } from "./useInstance";
import { useDriftStatus } from "./useDriftStatus";
import { useIdentities } from "./useIdentities";
import type { ReactNode } from "react";

function makeWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
}

describe("useInstance", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("fetches instance by id", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ id: "i1", integration_type: "slack" }), { status: 200 })
    );
    const { result } = renderHook(() => useInstance("i1"), { wrapper: makeWrapper() });
    await waitFor(() => expect(result.current.data).toBeDefined());
    expect(result.current.data).toEqual({ id: "i1", integration_type: "slack" });
  });
});

describe("useDriftStatus", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("fetches drift status by integration_type", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ in_sync: true, last_sync_at: "2026-05-17T10:00:00Z" }), { status: 200 })
    );
    const { result } = renderHook(() => useDriftStatus("slack"), { wrapper: makeWrapper() });
    await waitFor(() => expect(result.current.data).toBeDefined());
    expect(result.current.data?.in_sync).toBe(true);
  });
});

describe("useIdentities", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("fetches identities by integration_type", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ items: [{ id: "1", external_id: "U1" }], total: 1 }), { status: 200 })
    );
    const { result } = renderHook(() => useIdentities({ integrationType: "slack" }), {
      wrapper: makeWrapper()
    });
    await waitFor(() => expect(result.current.data).toBeDefined());
    expect(result.current.data?.items).toHaveLength(1);
  });
});
```

- [ ] **Step 2: Run — expect FAIL**

Run: `npm test -- data-hooks.test.tsx`
Expected: FAIL.

- [ ] **Step 3: Implement useInstance.ts**

```ts
import { useQuery } from "@tanstack/react-query";
import { useYggdrasilAPI } from "./useYggdrasilAPI";

export interface InstanceT {
  id: string;
  integration_type: string;
  name?: string;
  config?: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
}

export function useInstance(instanceId: string | undefined) {
  const api = useYggdrasilAPI();
  return useQuery({
    queryKey: ["instance", instanceId],
    enabled: !!instanceId,
    queryFn: () => api.get<InstanceT>(`/integration-instances/${instanceId}`),
    staleTime: 30_000
  });
}
```

- [ ] **Step 4: Implement useDriftStatus.ts**

```ts
import { useQuery } from "@tanstack/react-query";
import { useYggdrasilAPI } from "./useYggdrasilAPI";

export interface DriftStatusT {
  in_sync: boolean;
  last_sync_at?: string;
  declared_version?: string;
  running_version?: string;
  failures?: Array<{ field: string; reason: string }>;
}

export function useDriftStatus(integrationType: string) {
  const api = useYggdrasilAPI();
  return useQuery({
    queryKey: ["drift", integrationType],
    queryFn: () => api.get<DriftStatusT>(`/integration-types/${integrationType}/drift`),
    staleTime: 60_000
  });
}
```

- [ ] **Step 5: Implement useIdentities.ts**

```ts
import { useQuery } from "@tanstack/react-query";
import { useYggdrasilAPI } from "./useYggdrasilAPI";
import type { IdentityT } from "../components/IdentityRow";

export interface IdentitiesResult {
  items: IdentityT[];
  total: number;
}

export interface UseIdentitiesOpts {
  integrationType?: string;
  instanceId?: string;
  status?: "active" | "soft_deleted" | "all";
}

export function useIdentities(opts: UseIdentitiesOpts) {
  const api = useYggdrasilAPI();
  const params = new URLSearchParams();
  if (opts.integrationType) params.set("integration_type", opts.integrationType);
  if (opts.instanceId) params.set("instance_id", opts.instanceId);
  if (opts.status && opts.status !== "all") params.set("status", opts.status);
  const qs = params.toString() ? `?${params.toString()}` : "";
  return useQuery({
    queryKey: ["identities", opts],
    queryFn: () => api.get<IdentitiesResult>(`/collaborator-external-identities${qs}`),
    staleTime: 15_000
  });
}
```

- [ ] **Step 6: Run — expect PASS**

Run: `npm test -- data-hooks.test.tsx`
Expected: PASS — 3 tests.

- [ ] **Step 7: Wire exports**

Append to `src/hooks/index.ts`:

```ts
export { useInstance } from "./useInstance";
export type { InstanceT } from "./useInstance";
export { useDriftStatus } from "./useDriftStatus";
export type { DriftStatusT } from "./useDriftStatus";
export { useIdentities } from "./useIdentities";
export type { IdentitiesResult, UseIdentitiesOpts } from "./useIdentities";
```

- [ ] **Step 8: Commit**

```bash
git add src/hooks
git commit -m "feat(hooks): useInstance, useDriftStatus, useIdentities"
```

---

## Task 10: Data hooks — useActionCatalog, useRecentRuns, useWebhookLog, useSurfaceQuery

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/hooks/useActionCatalog.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/hooks/useRecentRuns.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/hooks/useWebhookLog.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/hooks/useSurfaceQuery.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/hooks/extra-hooks.test.tsx`

- [ ] **Step 1: Write failing test**

`src/hooks/extra-hooks.test.tsx`:

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useActionCatalog } from "./useActionCatalog";
import { useRecentRuns } from "./useRecentRuns";
import { useWebhookLog } from "./useWebhookLog";
import { useSurfaceQuery } from "./useSurfaceQuery";
import type { ReactNode } from "react";

function makeWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
}

describe("useActionCatalog", () => {
  beforeEach(() => vi.restoreAllMocks());
  it("fetches catalog for integration_type", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ items: [{ name: "on_create" }] }), { status: 200 })
    );
    const { result } = renderHook(() => useActionCatalog("slack"), { wrapper: makeWrapper() });
    await waitFor(() => expect(result.current.data).toBeDefined());
    expect(result.current.data?.items[0].name).toBe("on_create");
  });
});

describe("useRecentRuns", () => {
  beforeEach(() => vi.restoreAllMocks());
  it("fetches recent runs for instance", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ items: [], total: 0 }), { status: 200 })
    );
    const { result } = renderHook(() => useRecentRuns("i1"), { wrapper: makeWrapper() });
    await waitFor(() => expect(result.current.data).toBeDefined());
  });
});

describe("useWebhookLog", () => {
  beforeEach(() => vi.restoreAllMocks());
  it("fetches webhook audit events", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ items: [], total: 0 }), { status: 200 })
    );
    const { result } = renderHook(() => useWebhookLog("i1"), { wrapper: makeWrapper() });
    await waitFor(() => expect(result.current.data).toBeDefined());
  });
});

describe("useSurfaceQuery", () => {
  beforeEach(() => vi.restoreAllMocks());
  it("posts to surface-query proxy with named query", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ result: ["a", "b"] }), { status: 200 })
    );
    const { result } = renderHook(
      () => useSurfaceQuery("i1", "list-channels", { filter: "all" }),
      { wrapper: makeWrapper() }
    );
    await waitFor(() => expect(result.current.data).toBeDefined());
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/integrations/i1/surface-query",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ query_name: "list-channels", params: { filter: "all" } })
      })
    );
  });
});
```

- [ ] **Step 2: Run — expect FAIL**

Run: `npm test -- extra-hooks.test.tsx`
Expected: FAIL.

- [ ] **Step 3: Implement useActionCatalog.ts**

```ts
import { useQuery } from "@tanstack/react-query";
import { useYggdrasilAPI } from "./useYggdrasilAPI";

export interface ActionDef {
  name: string;
  resource_types?: string[];
  inputs?: Record<string, unknown>;
}

export interface ActionCatalogResult {
  items: ActionDef[];
}

export function useActionCatalog(integrationType: string) {
  const api = useYggdrasilAPI();
  return useQuery({
    queryKey: ["action-catalog", integrationType],
    queryFn: () =>
      api.get<ActionCatalogResult>(`/action-catalog?integration_type=${encodeURIComponent(integrationType)}`),
    staleTime: 5 * 60_000
  });
}
```

- [ ] **Step 4: Implement useRecentRuns.ts**

```ts
import { useQuery } from "@tanstack/react-query";
import { useYggdrasilAPI } from "./useYggdrasilAPI";

export interface RunT {
  id: string;
  workflow_name: string;
  status: "running" | "success" | "failed" | "queued";
  started_at: string;
  duration_ms?: number;
  capability?: string;
}

export interface RecentRunsResult {
  items: RunT[];
  total: number;
}

export function useRecentRuns(instanceId: string | undefined, limit = 25) {
  const api = useYggdrasilAPI();
  return useQuery({
    queryKey: ["recent-runs", instanceId, limit],
    enabled: !!instanceId,
    queryFn: () =>
      api.get<RecentRunsResult>(
        `/workflow-runs?integration_instance_id=${instanceId}&limit=${limit}&order=desc`
      ),
    staleTime: 10_000
  });
}
```

- [ ] **Step 5: Implement useWebhookLog.ts**

```ts
import { useQuery } from "@tanstack/react-query";
import { useYggdrasilAPI } from "./useYggdrasilAPI";

export interface WebhookEventT {
  id: string;
  event_type: string;
  signature_verified: boolean;
  received_at: string;
  payload_preview?: string;
}

export interface WebhookLogResult {
  items: WebhookEventT[];
  total: number;
}

export function useWebhookLog(instanceId: string | undefined, limit = 50) {
  const api = useYggdrasilAPI();
  return useQuery({
    queryKey: ["webhook-log", instanceId, limit],
    enabled: !!instanceId,
    queryFn: () =>
      api.get<WebhookLogResult>(
        `/audit-events?source=webhook&integration_id=${instanceId}&limit=${limit}&order=desc`
      ),
    staleTime: 10_000
  });
}
```

- [ ] **Step 6: Implement useSurfaceQuery.ts**

```ts
import { useQuery } from "@tanstack/react-query";
import { useYggdrasilAPI } from "./useYggdrasilAPI";

export function useSurfaceQuery<TResult = unknown>(
  instanceId: string | undefined,
  queryName: string,
  params: Record<string, unknown> = {}
) {
  const api = useYggdrasilAPI();
  return useQuery({
    queryKey: ["surface-query", instanceId, queryName, params],
    enabled: !!instanceId,
    queryFn: () =>
      api.post<TResult>(`/integrations/${instanceId}/surface-query`, {
        query_name: queryName,
        params
      }),
    staleTime: 15_000
  });
}
```

- [ ] **Step 7: Run — expect PASS**

Run: `npm test -- extra-hooks.test.tsx`
Expected: PASS — 4 tests.

- [ ] **Step 8: Wire exports**

Append to `src/hooks/index.ts`:

```ts
export { useActionCatalog } from "./useActionCatalog";
export type { ActionCatalogResult, ActionDef } from "./useActionCatalog";
export { useRecentRuns } from "./useRecentRuns";
export type { RecentRunsResult, RunT } from "./useRecentRuns";
export { useWebhookLog } from "./useWebhookLog";
export type { WebhookLogResult, WebhookEventT } from "./useWebhookLog";
export { useSurfaceQuery } from "./useSurfaceQuery";
```

- [ ] **Step 9: Commit**

```bash
git add src/hooks
git commit -m "feat(hooks): useActionCatalog, useRecentRuns, useWebhookLog, useSurfaceQuery"
```

---

## Task 11: OverviewTab + DriftTab (mandatory tab components)

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/tabs/OverviewTab.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/tabs/DriftTab.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/tabs/index.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/tabs/mandatory.test.tsx`

- [ ] **Step 1: Write failing test**

`src/tabs/mandatory.test.tsx`:

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { OverviewTab } from "./OverviewTab";
import { DriftTab } from "./DriftTab";

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>{ui}</QueryClientProvider>
    </MemoryRouter>
  );
}

describe("OverviewTab", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("shows instance config without secrets", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          id: "i1",
          integration_type: "slack",
          name: "prod-slack",
          config: { base_url: "https://slack.com", token: "REDACTED" },
          updated_at: new Date().toISOString()
        }),
        { status: 200 }
      )
    );
    wrap(<OverviewTab instanceId="i1" integrationType="slack" />);
    await waitFor(() => expect(screen.getByText("prod-slack")).toBeInTheDocument());
    expect(screen.getByText(/base_url/)).toBeInTheDocument();
  });
});

describe("DriftTab", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("shows in-sync badge when drift status is healthy", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          in_sync: true,
          last_sync_at: new Date().toISOString(),
          declared_version: "1.3.0",
          running_version: "1.3.0"
        }),
        { status: 200 }
      )
    );
    wrap(<DriftTab instanceId="i1" integrationType="slack" />);
    await waitFor(() => expect(screen.getByText(/sincronizad/i)).toBeInTheDocument());
  });

  it("shows drift badge when out-of-sync", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          in_sync: false,
          last_sync_at: new Date().toISOString(),
          declared_version: "1.3.0",
          running_version: "1.2.1",
          failures: [{ field: "version", reason: "mismatch" }]
        }),
        { status: 200 }
      )
    );
    wrap(<DriftTab instanceId="i1" integrationType="slack" />);
    await waitFor(() => expect(screen.getByText(/drift/i)).toBeInTheDocument());
  });
});
```

- [ ] **Step 2: Run — expect FAIL**

Run: `npm test -- mandatory.test.tsx`
Expected: FAIL.

- [ ] **Step 3: Implement OverviewTab.tsx**

```tsx
import { Stack, Typography, Paper } from "@mui/material";
import { useInstance } from "../hooks/useInstance";
import { LoadingState } from "../components/LoadingState";
import { EmptyState } from "../components/EmptyState";
import { JsonViewer } from "../components/JsonViewer";
import { TimestampRelative } from "../components/TimestampRelative";

export interface OverviewTabProps {
  instanceId: string;
  integrationType: string;
}

function sanitizeConfig(config: Record<string, unknown> | undefined): Record<string, unknown> {
  if (!config) return {};
  const SENSITIVE = new Set(["token", "secret", "password", "api_key", "private_key"]);
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(config)) {
    out[k] = SENSITIVE.has(k.toLowerCase()) ? "•••" : v;
  }
  return out;
}

export function OverviewTab({ instanceId }: OverviewTabProps) {
  const { data, isLoading, error } = useInstance(instanceId);
  if (isLoading) return <LoadingState />;
  if (error || !data) return <EmptyState title="Sem dados" description="Não foi possível carregar a instância." />;
  return (
    <Stack spacing={2}>
      <Typography variant="h6">{data.name ?? data.id}</Typography>
      <Paper variant="outlined" sx={{ p: 2 }}>
        <Stack spacing={1}>
          <Typography variant="caption" color="text.secondary">
            Atualizado
          </Typography>
          <Typography variant="body2">
            {data.updated_at ? <TimestampRelative isoString={data.updated_at} /> : "—"}
          </Typography>
        </Stack>
      </Paper>
      <Paper variant="outlined" sx={{ p: 2 }}>
        <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: "block" }}>
          Configuração
        </Typography>
        <JsonViewer value={sanitizeConfig(data.config)} />
      </Paper>
    </Stack>
  );
}
```

- [ ] **Step 4: Implement DriftTab.tsx**

```tsx
import { Stack, Typography, Paper, Alert, AlertTitle } from "@mui/material";
import { useDriftStatus } from "../hooks/useDriftStatus";
import { LoadingState } from "../components/LoadingState";
import { EmptyState } from "../components/EmptyState";
import { DriftBadge } from "../components/DriftBadge";
import { TimestampRelative } from "../components/TimestampRelative";

export interface DriftTabProps {
  instanceId: string;
  integrationType: string;
}

export function DriftTab({ integrationType }: DriftTabProps) {
  const { data, isLoading, error } = useDriftStatus(integrationType);
  if (isLoading) return <LoadingState />;
  if (error || !data) return <EmptyState title="Sem dados de drift" />;
  return (
    <Stack spacing={2}>
      <Stack direction="row" alignItems="center" spacing={2}>
        <DriftBadge inSync={data.in_sync} />
        {data.last_sync_at ? (
          <Typography variant="caption" color="text.secondary">
            Último sync: <TimestampRelative isoString={data.last_sync_at} />
          </Typography>
        ) : null}
      </Stack>
      <Paper variant="outlined" sx={{ p: 2 }}>
        <Typography variant="body2">
          Versão declarada: <strong>{data.declared_version ?? "—"}</strong>
        </Typography>
        <Typography variant="body2">
          Versão em runtime: <strong>{data.running_version ?? "—"}</strong>
        </Typography>
      </Paper>
      {data.failures && data.failures.length > 0 ? (
        <Alert severity="warning">
          <AlertTitle>Falhas de validação</AlertTitle>
          <ul>
            {data.failures.map((f, idx) => (
              <li key={idx}>
                <strong>{f.field}:</strong> {f.reason}
              </li>
            ))}
          </ul>
        </Alert>
      ) : null}
    </Stack>
  );
}
```

- [ ] **Step 5: Implement index.ts**

`src/tabs/index.ts`:

```ts
export { OverviewTab } from "./OverviewTab";
export type { OverviewTabProps } from "./OverviewTab";
export { DriftTab } from "./DriftTab";
export type { DriftTabProps } from "./DriftTab";
```

Append to `src/index.ts`:

```ts
export * from "./tabs";
```

- [ ] **Step 6: Run — expect PASS**

Run: `npm test -- mandatory.test.tsx`
Expected: PASS — 3 tests.

- [ ] **Step 7: Commit**

```bash
git add src/tabs src/index.ts
git commit -m "feat(tabs): OverviewTab + DriftTab (mandatory tab components)"
```

---

## Task 12: Opt-in tabs — IdentitiesTab, ActionsTab, RecentRunsTab, WebhookLogTab, ResourcesTab

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/tabs/IdentitiesTab.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/tabs/ActionsTab.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/tabs/RecentRunsTab.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/tabs/WebhookLogTab.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/tabs/ResourcesTab.tsx`
- Modify: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/tabs/index.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/tabs/opt-in.test.tsx`

- [ ] **Step 1: Write failing test (one for each tab)**

`src/tabs/opt-in.test.tsx`:

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { IdentitiesTab } from "./IdentitiesTab";
import { ActionsTab } from "./ActionsTab";
import { RecentRunsTab } from "./RecentRunsTab";
import { WebhookLogTab } from "./WebhookLogTab";
import { ResourcesTab } from "./ResourcesTab";

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>{ui}</QueryClientProvider>
    </MemoryRouter>
  );
}

describe("IdentitiesTab", () => {
  beforeEach(() => vi.restoreAllMocks());
  it("renders identities list", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            { id: "1", collaborator_email: "alice@dakasa.me", external_id: "U1", status: "active" }
          ],
          total: 1
        }),
        { status: 200 }
      )
    );
    wrap(<IdentitiesTab instanceId="i1" integrationType="slack" />);
    await waitFor(() => expect(screen.getByText("alice@dakasa.me")).toBeInTheDocument());
  });
});

describe("ActionsTab", () => {
  beforeEach(() => vi.restoreAllMocks());
  it("renders action catalog", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ items: [{ name: "on_create_user" }, { name: "on_disable_user" }] }), {
        status: 200
      })
    );
    wrap(<ActionsTab instanceId="i1" integrationType="slack" />);
    await waitFor(() => expect(screen.getByText("on_create_user")).toBeInTheDocument());
  });
});

describe("RecentRunsTab", () => {
  beforeEach(() => vi.restoreAllMocks());
  it("renders runs", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            {
              id: "r1",
              workflow_name: "onboard",
              status: "success",
              started_at: new Date().toISOString()
            }
          ],
          total: 1
        }),
        { status: 200 }
      )
    );
    wrap(<RecentRunsTab instanceId="i1" integrationType="slack" />);
    await waitFor(() => expect(screen.getByText("onboard")).toBeInTheDocument());
  });
});

describe("WebhookLogTab", () => {
  beforeEach(() => vi.restoreAllMocks());
  it("renders webhook events", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            {
              id: "w1",
              event_type: "issues.opened",
              signature_verified: true,
              received_at: new Date().toISOString()
            }
          ],
          total: 1
        }),
        { status: 200 }
      )
    );
    wrap(<WebhookLogTab instanceId="i1" integrationType="github" />);
    await waitFor(() => expect(screen.getByText("issues.opened")).toBeInTheDocument());
  });
});

describe("ResourcesTab", () => {
  beforeEach(() => vi.restoreAllMocks());
  it("renders resource list via surface-query", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            { id: "C1", name: "general", kind: "channel" },
            { id: "C2", name: "random", kind: "channel" }
          ]
        }),
        { status: 200 }
      )
    );
    wrap(<ResourcesTab instanceId="i1" integrationType="slack" queryName="list-resources" />);
    await waitFor(() => expect(screen.getByText("general")).toBeInTheDocument());
  });
});
```

- [ ] **Step 2: Run — expect FAIL**

Run: `npm test -- opt-in.test.tsx`
Expected: FAIL.

- [ ] **Step 3: Implement IdentitiesTab.tsx**

```tsx
import { Stack } from "@mui/material";
import { useIdentities } from "../hooks/useIdentities";
import { LoadingState } from "../components/LoadingState";
import { EmptyState } from "../components/EmptyState";
import { IdentityRow } from "../components/IdentityRow";

export interface IdentitiesTabProps {
  instanceId: string;
  integrationType: string;
}

export function IdentitiesTab({ instanceId, integrationType }: IdentitiesTabProps) {
  const { data, isLoading } = useIdentities({ instanceId, integrationType });
  if (isLoading) return <LoadingState />;
  if (!data || data.items.length === 0) {
    return <EmptyState title="Nenhuma identidade vinculada" description="As identidades aparecem após o primeiro onboard." />;
  }
  return (
    <Stack>
      {data.items.map((id) => (
        <IdentityRow key={id.id} identity={id} />
      ))}
    </Stack>
  );
}
```

- [ ] **Step 4: Implement ActionsTab.tsx**

```tsx
import { useActionCatalog } from "../hooks/useActionCatalog";
import { LoadingState } from "../components/LoadingState";
import { EmptyState } from "../components/EmptyState";
import { DataTable } from "../components/DataTable";
import type { ActionDef } from "../hooks/useActionCatalog";

export interface ActionsTabProps {
  instanceId: string;
  integrationType: string;
}

export function ActionsTab({ integrationType }: ActionsTabProps) {
  const { data, isLoading } = useActionCatalog(integrationType);
  if (isLoading) return <LoadingState />;
  if (!data || data.items.length === 0) {
    return <EmptyState title="Nenhuma action declarada" />;
  }
  return (
    <DataTable<ActionDef>
      rows={data.items}
      keyField="name"
      columns={[
        { id: "name", header: "Action", accessor: (r) => r.name, sortable: true },
        {
          id: "resources",
          header: "Resources",
          accessor: (r) => (r.resource_types ? r.resource_types.join(", ") : "—")
        }
      ]}
    />
  );
}
```

- [ ] **Step 5: Implement RecentRunsTab.tsx**

```tsx
import { useRecentRuns, type RunT } from "../hooks/useRecentRuns";
import { LoadingState } from "../components/LoadingState";
import { EmptyState } from "../components/EmptyState";
import { DataTable } from "../components/DataTable";
import { TimestampRelative } from "../components/TimestampRelative";

export interface RecentRunsTabProps {
  instanceId: string;
  integrationType: string;
}

export function RecentRunsTab({ instanceId }: RecentRunsTabProps) {
  const { data, isLoading } = useRecentRuns(instanceId);
  if (isLoading) return <LoadingState />;
  if (!data || data.items.length === 0) {
    return <EmptyState title="Nenhuma execução recente" />;
  }
  return (
    <DataTable<RunT>
      rows={data.items}
      keyField="id"
      columns={[
        { id: "workflow", header: "Workflow", accessor: (r) => r.workflow_name, sortable: true },
        { id: "status", header: "Status", accessor: (r) => r.status, sortable: true },
        {
          id: "started",
          header: "Iniciado",
          accessor: (r) => <TimestampRelative isoString={r.started_at} />
        }
      ]}
    />
  );
}
```

- [ ] **Step 6: Implement WebhookLogTab.tsx**

```tsx
import { useWebhookLog, type WebhookEventT } from "../hooks/useWebhookLog";
import { LoadingState } from "../components/LoadingState";
import { EmptyState } from "../components/EmptyState";
import { DataTable } from "../components/DataTable";
import { TimestampRelative } from "../components/TimestampRelative";

export interface WebhookLogTabProps {
  instanceId: string;
  integrationType: string;
}

export function WebhookLogTab({ instanceId }: WebhookLogTabProps) {
  const { data, isLoading } = useWebhookLog(instanceId);
  if (isLoading) return <LoadingState />;
  if (!data || data.items.length === 0) {
    return <EmptyState title="Nenhum webhook recebido" />;
  }
  return (
    <DataTable<WebhookEventT>
      rows={data.items}
      keyField="id"
      columns={[
        { id: "event", header: "Evento", accessor: (r) => r.event_type, sortable: true },
        {
          id: "verified",
          header: "Assinatura",
          accessor: (r) => (r.signature_verified ? "✓" : "✗")
        },
        {
          id: "received",
          header: "Recebido",
          accessor: (r) => <TimestampRelative isoString={r.received_at} />
        }
      ]}
    />
  );
}
```

- [ ] **Step 7: Implement ResourcesTab.tsx**

```tsx
import { useSurfaceQuery } from "../hooks/useSurfaceQuery";
import { LoadingState } from "../components/LoadingState";
import { EmptyState } from "../components/EmptyState";
import { DataTable, type ColumnDef } from "../components/DataTable";

export interface ResourceItem extends Record<string, unknown> {
  id: string;
  name?: string;
  kind?: string;
}

export interface ResourcesTabProps {
  instanceId: string;
  integrationType: string;
  queryName?: string; // defaults "list-resources"
  columns?: ColumnDef<ResourceItem>[];
}

const defaultCols: ColumnDef<ResourceItem>[] = [
  { id: "name", header: "Nome", accessor: (r) => r.name ?? r.id, sortable: true },
  { id: "kind", header: "Tipo", accessor: (r) => r.kind ?? "—" }
];

export function ResourcesTab({ instanceId, queryName = "list-resources", columns = defaultCols }: ResourcesTabProps) {
  const { data, isLoading } = useSurfaceQuery<{ items: ResourceItem[] }>(instanceId, queryName);
  if (isLoading) return <LoadingState />;
  if (!data || !data.items || data.items.length === 0) {
    return <EmptyState title="Nenhum recurso" />;
  }
  return <DataTable<ResourceItem> rows={data.items} keyField="id" columns={columns} />;
}
```

- [ ] **Step 8: Wire exports**

Append to `src/tabs/index.ts`:

```ts
export { IdentitiesTab } from "./IdentitiesTab";
export type { IdentitiesTabProps } from "./IdentitiesTab";
export { ActionsTab } from "./ActionsTab";
export type { ActionsTabProps } from "./ActionsTab";
export { RecentRunsTab } from "./RecentRunsTab";
export type { RecentRunsTabProps } from "./RecentRunsTab";
export { WebhookLogTab } from "./WebhookLogTab";
export type { WebhookLogTabProps } from "./WebhookLogTab";
export { ResourcesTab } from "./ResourcesTab";
export type { ResourcesTabProps, ResourceItem } from "./ResourcesTab";
```

- [ ] **Step 9: Run — expect PASS**

Run: `npm test -- opt-in.test.tsx`
Expected: PASS — 5 tests.

- [ ] **Step 10: Commit**

```bash
git add src/tabs
git commit -m "feat(tabs): IdentitiesTab, ActionsTab, RecentRunsTab, WebhookLogTab, ResourcesTab"
```

---

## Task 13: IntegrationAdminShell

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/shell/IntegrationAdminShell.tsx`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/shell/index.ts`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/src/shell/IntegrationAdminShell.test.tsx`

- [ ] **Step 1: Write failing test**

`src/shell/IntegrationAdminShell.test.tsx`:

```tsx
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { IntegrationAdminShell } from "./IntegrationAdminShell";

function makeWrapper(initialEntry: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: React.ReactNode }) => (
    <MemoryRouter initialEntries={[initialEntry]}>
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    </MemoryRouter>
  );
}

function TestShell() {
  const tabs = [
    { id: "overview", label: "Overview", component: () => <div>Overview body</div> },
    { id: "drift", label: "Drift", component: () => <div>Drift body</div> }
  ];
  return (
    <Routes>
      <Route
        path="/s/slack/instance/:instanceId/:tabId"
        element={<IntegrationAdminShell integrationType="slack" tabs={tabs} basePath="/s/slack" />}
      />
      <Route
        path="/s/slack/instance/:instanceId"
        element={<IntegrationAdminShell integrationType="slack" tabs={tabs} basePath="/s/slack" />}
      />
    </Routes>
  );
}

describe("IntegrationAdminShell", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders the first tab when no tabId in path", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ id: "i1", integration_type: "slack" }), { status: 200 })
    );
    const Wrapper = makeWrapper("/s/slack/instance/i1");
    render(<TestShell />, { wrapper: Wrapper });
    await waitFor(() => expect(screen.getByText("Overview body")).toBeInTheDocument());
  });

  it("switches tabs via tab click", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ id: "i1", integration_type: "slack" }), { status: 200 })
    );
    const Wrapper = makeWrapper("/s/slack/instance/i1/overview");
    const user = userEvent.setup();
    render(<TestShell />, { wrapper: Wrapper });
    await waitFor(() => expect(screen.getByText("Overview body")).toBeInTheDocument());
    await user.click(screen.getByRole("tab", { name: "Drift" }));
    await waitFor(() => expect(screen.getByText("Drift body")).toBeInTheDocument());
  });
});
```

- [ ] **Step 2: Run — expect FAIL**

Run: `npm test -- IntegrationAdminShell.test.tsx`
Expected: FAIL.

- [ ] **Step 3: Implement IntegrationAdminShell.tsx**

```tsx
import type { ComponentType } from "react";
import { Box, Stack } from "@mui/material";
import { useParams, Navigate } from "react-router-dom";
import { Tabs, type TabDef, TabPanel } from "../components/Tabs";
import { PageHeader } from "../components/PageHeader";
import { LoadingState } from "../components/LoadingState";
import { EmptyState } from "../components/EmptyState";
import { useInstance } from "../hooks/useInstance";

export interface TabDefinition {
  id: string;
  label: string;
  component: ComponentType<{ instanceId: string; integrationType: string }>;
}

export interface IntegrationAdminShellProps {
  integrationType: string;
  tabs: TabDefinition[];
  basePath: string; // e.g., "/s/slack"
  title?: string;
  subtitle?: string;
}

export function IntegrationAdminShell({
  integrationType,
  tabs,
  basePath,
  title,
  subtitle
}: IntegrationAdminShellProps) {
  const { instanceId, tabId } = useParams<{ instanceId: string; tabId: string }>();
  const { data: instance, isLoading, error } = useInstance(instanceId);

  if (!instanceId) return <EmptyState title="Instance ausente" description="URL inválida." />;
  if (isLoading) return <LoadingState />;
  if (error || !instance) {
    return <EmptyState title="Instance não encontrada" description="Verifique se ela ainda existe." />;
  }

  const firstTabId = tabs[0]?.id ?? "overview";
  if (!tabId) {
    return <Navigate replace to={`${basePath}/instance/${instanceId}/${firstTabId}`} />;
  }

  const tabDefs: TabDef[] = tabs.map((t) => ({ id: t.id, label: t.label }));
  const tabBase = `${basePath}/instance/${instanceId}`;

  return (
    <Box sx={{ p: 3 }}>
      <PageHeader
        title={title ?? instance.name ?? instance.id}
        subtitle={subtitle ?? integrationType}
        breadcrumb={[
          { label: "Integrações", to: "/ops/integrations" },
          { label: integrationType }
        ]}
      />
      <Stack spacing={2}>
        <Tabs items={tabDefs} basePath={tabBase} />
        {tabs.map((t) => {
          const Body = t.component;
          return (
            <TabPanel key={t.id} id={t.id}>
              <Body instanceId={instanceId} integrationType={integrationType} />
            </TabPanel>
          );
        })}
      </Stack>
    </Box>
  );
}
```

- [ ] **Step 4: Wire export**

`src/shell/index.ts`:

```ts
export { IntegrationAdminShell } from "./IntegrationAdminShell";
export type { IntegrationAdminShellProps, TabDefinition } from "./IntegrationAdminShell";
```

Append to `src/index.ts`:

```ts
export * from "./shell";
```

- [ ] **Step 5: Run — expect PASS**

Run: `npm test -- IntegrationAdminShell.test.tsx`
Expected: PASS — 2 tests.

- [ ] **Step 6: Commit**

```bash
git add src/shell src/index.ts
git commit -m "feat(shell): IntegrationAdminShell — orchestrator with router-driven tabs"
```

---

## Task 14: Build library + verify

**Files:**
- Modify: nothing (build only)

- [ ] **Step 1: Build the package**

```bash
cd /Users/dakasa/projects/yggdrasil/surface-toolkit
npm run build
```

Expected: `dist/` directory created with `index.js`, `index.cjs`, `index.d.ts`. No build errors.

- [ ] **Step 2: Verify dist contents**

```bash
ls dist/
```

Expected output includes: `index.js`, `index.cjs`, `index.d.ts`, and source maps.

- [ ] **Step 3: Smoke check exports by reading the dts**

```bash
grep -E "export \{|export type" dist/index.d.ts | head -30
```

Expected: lines exporting `IntegrationAdminShell`, `OverviewTab`, `DriftTab`, `IdentitiesTab`, `useYggdrasilAPI`, `tokens`, etc.

- [ ] **Step 4: Run full test suite**

```bash
npm test
```

Expected: all tests across all files green (38+ total).

- [ ] **Step 5: Commit build verification (no file change; tag this with empty commit for sync gate)**

```bash
git commit --allow-empty -m "chore: surface-toolkit v0.1.0 build & tests green"
```

---

## Task 15: Publish workflow + GH Actions

**Files:**
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/.github/workflows/ci.yml`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/.github/workflows/publish.yml`
- Create: `/Users/dakasa/projects/yggdrasil/surface-toolkit/LICENSE`

- [ ] **Step 1: Write LICENSE (Apache-2.0)**

`LICENSE`:

```
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   Copyright 2026 DaKasa

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0
```

(Full text omitted for brevity; copy in full from https://www.apache.org/licenses/LICENSE-2.0.txt — implementer copies the full standard text.)

- [ ] **Step 2: Write CI workflow**

`.github/workflows/ci.yml`:

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm
      - run: npm ci
      - run: npm run lint
      - run: npm test
      - run: npm run build
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
          retention-days: 7
```

- [ ] **Step 3: Write publish workflow**

`.github/workflows/publish.yml`:

```yaml
name: Publish to GHCR npm
on:
  push:
    tags: ["v*"]

permissions:
  contents: read
  packages: write

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          registry-url: "https://npm.pkg.github.com"
          scope: "@yggdrasil"
      - run: npm ci
      - run: npm test
      - run: npm run build
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

- [ ] **Step 4: Commit workflows**

```bash
git add .github LICENSE
git commit -m "ci: GH Actions for test on main + publish on tag"
```

- [ ] **Step 5: Final tag for v0.1.0**

```bash
git tag v0.1.0
```

(Tag created locally; pushing the tag happens during execution flow, not at plan time.)

- [ ] **Step 6: Smoke install test (manual; in a scratch dir)**

In a separate shell, after the package is published (or via local `npm pack`):

```bash
cd /tmp && mkdir surface-smoke && cd surface-smoke
npm init -y
npm install /Users/dakasa/projects/yggdrasil/surface-toolkit
cat > test-import.mjs <<'EOF'
import * as toolkit from "@yggdrasil/surface-toolkit";
const expected = ["tokens", "IntegrationIcon", "LoadingState", "EmptyState", "ErrorBoundary",
                  "PageHeader", "Tabs", "TabPanel", "DataTable",
                  "JsonViewer", "TimestampRelative", "HealthBadge", "DriftBadge", "IdentityRow",
                  "useYggdrasilAPI", "useInstance", "useDriftStatus", "useIdentities",
                  "useActionCatalog", "useRecentRuns", "useWebhookLog", "useSurfaceQuery",
                  "OverviewTab", "DriftTab", "IdentitiesTab", "ActionsTab", "RecentRunsTab",
                  "WebhookLogTab", "ResourcesTab", "IntegrationAdminShell"];
const missing = expected.filter(name => !(name in toolkit));
if (missing.length) { console.error("MISSING:", missing); process.exit(1); }
console.log("ALL EXPORTS PRESENT");
EOF
node test-import.mjs
```

Expected: `ALL EXPORTS PRESENT`

- [ ] **Step 7: Commit empty marker for Phase 0a complete**

```bash
cd /Users/dakasa/projects/yggdrasil/surface-toolkit
git commit --allow-empty -m "chore: Phase 0a complete — surface-toolkit @0.1.0 ready"
```

---

## Phase 0a sync gate (after Task 15)

Before Phase 0b/0c/0d may consume this toolkit:

1. ✅ All 38+ unit tests passing
2. ✅ `npm run build` produces clean `dist/` with `.d.ts`
3. ✅ Smoke-install verification shows all named exports
4. ✅ Tag `v0.1.0` exists locally; will be pushed by orchestrator after final review
5. ✅ Repo committed to `dakasa-yggdrasil/surface-toolkit` (push when granted)

---

## Final code reviewer dispatch (after Task 15)

Per subagent-driven-development skill, after all tasks complete, dispatch one final code reviewer subagent over the whole implementation. Reviewer checks:
- All exports listed in spec §6.2 are present
- No leaked secret fields in OverviewTab (`sanitizeConfig` covers token/secret/password/api_key/private_key)
- TypeScript strict mode with no `any` (except in test fixture rows where intentional)
- All exported hooks use `useQuery` from `@tanstack/react-query` (no homegrown fetch caching)
- Peer dependencies pinned to caret versions matching surface-console (react 19, react-router-dom 7, etc.)

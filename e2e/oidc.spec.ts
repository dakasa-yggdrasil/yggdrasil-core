// OIDC end-to-end smoke spec — Phase 1 skeleton.
//
// Status: SKIPPED. The flows under test cross repository boundaries
// (Tartaro frontend + backend, dakasa-commons/oidcclient) that are not
// yet wired into Yggdrasil-core. Once Phase 1 Tasks 13–15 land and a
// validation cluster is reachable, fill in these specs by following
// docs/oidc-e2e-smoke.md.
//
// Run locally against a deployed cluster (uses the validation overlay
// by default; override BASE via env):
//
//   BASE=https://yggdrasil.dakasa.me TARTARO=https://tartaro.dakasa.me \
//     npx playwright test e2e/oidc.spec.ts
//
// Per-test prerequisites are spelled out in the manual checklist file.

import { test, expect } from '@playwright/test';

const BASE = process.env.BASE ?? 'https://yggdrasil.dakasa.me';
const TARTARO = process.env.TARTARO ?? 'https://tartaro.dakasa.me';

test.describe('OIDC end-to-end (Phase 1)', () => {
  test.skip(true, 'enable after Phase 1 Tasks 13–15 land + validation cluster reachable');

  test('discovery document is well-formed and points to known endpoints', async ({ request }) => {
    const resp = await request.get(`${BASE}/.well-known/openid-configuration`);
    expect(resp.status()).toBe(200);
    const doc = await resp.json();
    expect(doc.issuer).toBe(BASE);
    expect(doc.authorization_endpoint).toMatch(/\/authorize$/);
    expect(doc.token_endpoint).toMatch(/\/token$/);
    expect(doc.jwks_uri).toMatch(/\/keys$/);
    expect(doc.id_token_signing_alg_values_supported).toContain('RS256');
  });

  test('jwks endpoint returns at least one active RS256 key', async ({ request }) => {
    const resp = await request.get(`${BASE}/oidc/keys`);
    expect(resp.status()).toBe(200);
    const jwks = await resp.json();
    expect(Array.isArray(jwks.keys)).toBeTruthy();
    expect(jwks.keys.length).toBeGreaterThan(0);
    expect(jwks.keys[0].alg).toBe('RS256');
    expect(jwks.keys[0].kty).toBe('RSA');
  });

  test('console root redirects to Google for unauthenticated user', async ({ page }) => {
    const resp = await page.goto(`${BASE}/console/`);
    // Either we redirect to Google immediately, or to /authorize which
    // then redirects to Google. Either way the final origin must be Google.
    expect(page.url()).toContain('accounts.google.com');
    expect(resp?.status()).toBeLessThan(400);
  });

  test('full login round-trip: console → google → back → claims visible', async ({ page }) => {
    // This requires a Google test account with workspace SSO; deferred
    // until we have credentials in CI vault. See manual checklist for
    // the human-driven equivalent.
    test.fixme(true, 'Google credentials not in CI vault yet');

    await page.goto(`${BASE}/console/`);
    await page.fill('input[type="email"]', process.env.TEST_GOOGLE_USER!);
    // ... finish flow, assert claims display
  });

  test('tartaro reuses cookie: no Google prompt on second app', async ({ page }) => {
    test.fixme(true, 'depends on full login first');

    await page.goto(TARTARO);
    expect(page.url()).not.toContain('accounts.google.com');
    await expect(page.locator('[data-test="claim-name"]')).toBeVisible();
  });
});

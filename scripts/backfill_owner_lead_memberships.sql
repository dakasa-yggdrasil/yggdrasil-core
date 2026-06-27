-- Backfill: ensure every team owner has an ACTIVE team_memberships row.
--
-- Mirrors repository.ensureOwnerMemberships (repository/identity.go): leadership is
-- sourced from teams.owners, but every reader joins through team_memberships, so an
-- owner with no membership row is invisible (RBAC + /me omit them). This backfill closes
-- that gap for teams that already exist.
--
-- PRESERVE semantics (decided 2026-06-26): role='lead' + source='owner-sync' apply ONLY
-- when INSERTing a brand-new membership. An owner who already has a membership keeps its
-- existing role (e.g. 'founder', 'base-employee') and source — the ON CONFLICT clause only
-- (re)activates it. Idempotent: a second run changes nothing (active rows are skipped by the
-- DO UPDATE ... WHERE active IS DISTINCT FROM true guard).
--
-- Owners that do not resolve to a collaborator are skipped (the JOIN drops them) — run the
-- diagnostic in the same dir to surface any such rows before backfilling.
--
-- Run:  psql "$DB_URL" -f scripts/backfill_owner_lead_memberships.sql
BEGIN;

INSERT INTO public.team_memberships (team_id, collaborator_id, role, active, source)
SELECT t.id, c.id, 'lead', true, 'owner-sync'
FROM public.teams t
CROSS JOIN LATERAL jsonb_array_elements_text(t.owners) AS o(owner_id)
JOIN public.collaborators c ON (c.id::text = o.owner_id OR c.slug = o.owner_id)
ON CONFLICT ON CONSTRAINT team_memberships_unique_link
DO UPDATE SET active = true, updated_at = NOW()
  WHERE public.team_memberships.active IS DISTINCT FROM true;

COMMIT;

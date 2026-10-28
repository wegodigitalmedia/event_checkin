# Release integration report

**Candidate branch:** `release/event-checkin-v1`
**Base UI release:** `8f47225` (`feat/platform-ui-ux-overhaul`)
**Preserved WIP snapshot:** `recovery/privacy-import-wip-20261028` at `8559f10`
**Integration snapshot:** `4294fe9`
**Deployment state:** no push, merge, deployment or external resource creation

## Release integration commits

- `7771e34` — `feat(release): finalize privacy and scanner contracts`
- `02c0f2f` — `feat(delivery): add authenticated Brevo transport`
- `39acf0c` — `ops(release): add production deployment topology`

## Integrated scope

- Preserved the completed Quiet Operations UI and event-context behavior while
  integrating the organization directory/detail/search/pagination workflow.
- Integrated tenant-scoped privacy notice draft, approval and activation with
  immutable approved content, actor/timestamp attribution, audit records and
  explicit import authorization evidence.
- Added typed FastAPI schemas and route contract coverage for organization,
  privacy and gate redemption APIs.
- Added stable scanner reason codes: `ACCEPTED`, `DUPLICATE_ADMISSION`,
  `REVOKED_TICKET`, `INVALID_TICKET`, `EVENT_UNAVAILABLE`, `GATE_UNAVAILABLE`,
  `CHECKIN_NOT_OPEN`, `CHECKIN_CLOSED`, `CHECKIN_WINDOW_UNAVAILABLE`. Only
  `accepted/ACCEPTED` authorizes admission; legacy outcome-only responses still
  render safely.
- Added Brevo API delivery for authentication and durable ticket-delivery jobs,
  intent idempotency, QR attachment, authenticated provider callbacks and
  delivery/bounce/error state updates.
- Added structured request/scanner logs and a Vercel -> authenticated Render
  origin topology with production examples and runbooks.

## Database and security findings

- Alembic history is linear through the single head
  `0013_privacy_notice_workflow`.
- Corrected the `0013` runtime column grant so privacy/import audit inserts can
  write actor, tenant, action and metadata while reading only generated ID/time.
- PostgreSQL integration tests create independent `NOBYPASSRLS` logins and
  validate FORCE RLS/tenant isolation. Platform notice access is scoped by
  transaction tenant context; platform sessions do not expose participants.
- Published event schedules remain immutable. Scanner context tests use separate
  synthetic events instead of weakening that trigger.
- Brevo secrets never enter browser bundles; the callback is Bearer-authenticated
  before request-body parsing and resolves delivery intent under tenant-scoped
  RLS. Normal API requests use least-privilege roles, not the migration owner.
- A review of the complete release diff found only explicit replacement
  placeholders and synthetic/local test credentials. No provider key, private
  key, populated environment file or database dump is included.

## Verification reported by prior sessions

| Area | Result |
|---|---|
| Ruff | passed |
| strict mypy | passed, 64 source files |
| backend non-PostgreSQL | 74 passed; 17 sync-ASGI contracts skipped only in this sandbox |
| PostgreSQL integration | 59 passed, 3 intentional skips |
| 5,000-row rehearsal | passed in 35.75 s; 25 chunks, 5,000 registrations/jobs, no email |
| Alembic | single head; empty-database upgrade/downgrade/upgrade passed through `0013_privacy_notice_workflow` |
| TypeScript | passed |
| ESLint | passed |
| frontend token/proxy tests | 4 passed |
| Vite production build | passed |
| complete Playwright integration/accessibility | 55 passed; corrected screenshot fixture also rerun in isolation |
| production image ingress | independently rechecked below; original test-mode readiness 200, production-mode readiness 503 against non-TLS local database |

The 5,000-row result is a database-integrity rehearsal, not production latency
or venue capacity evidence. The ingress result uses a local container and
disposable PostgreSQL database; it is not evidence about Render, Supabase,
Vercel, DNS, TLS, provider networking or production latency.

## Remaining release gates

- Synchronous FastAPI TestClient contracts cannot schedule their sync endpoint
  threadpool in this sandbox. Seventeen are skipped only when
  `SKIP_SYNC_ASGI_TESTS=1`; CI must run them without that variable.
- No production region, domains, credentials, DPA, Supabase restore test, Brevo
  sender/quota, or event-day latency SLO has been approved or exercised.
- A five-device staging/venue rehearsal and external HTTPS probes remain
  mandatory. No production load test or real bulk email was performed.
- `/ready` proves API/database only and reports worker `not_configured`; worker,
  dispatcher and queue health must be monitored independently as documented.
- The existing remote custom-domain provider remains disabled. The shared
  Vercel platform/fallback host is the production path unless an approved domain
  adapter is separately completed.

This candidate must not be called production-ready until the environment,
provider, restore, CI and venue gates above are signed off.

## Final handover verification — 2026-10-28

The release worktree is `.release-worktrees/event-checkin-v1`, on
`release/event-checkin-v1`. The parent workspace remains on
`recovery/privacy-import-wip-20261028` at `8559f10`; its untracked release
worktree directory is preserved. No reset, clean, stash, merge, push or external
deployment was performed.

Exact implementation commits:

- `7771e34407f7f44251b8bbe4bce537fff0ae9802`
- `02c0f2f41f3a727f5b6f58131991db118fe95d5f`
- `39acf0c70a7aaae5cef0cb592ab65ddad95ea80d`

The final documentation commit is the commit containing this section (obtain
its full SHA with `git rev-parse HEAD` on the release branch).

### Evidence provenance

The numerical results in the preceding table are prior-session reports, not
freshly rerun results. Original terminal logs establishing 59 PostgreSQL tests,
74 unit tests, 55 Playwright tests and the 35.75-second rehearsal were not found
in this worktree or accessible temporary artifacts. They cannot be independently
certified from the surviving evidence. `frontend/test-results/.last-run.json`
records `passed` with no failed tests; backend pytest `lastfailed` is `{}`.
Pytest node IDs and frontend `dist` assets survive, but neither proves test
counts, timings, TypeScript or lint success. Expensive suites were not repeated.
Retain CI logs for these results before deployment approval, including the 17
sync-ASGI contracts without `SKIP_SYNC_ASGI_TESTS=1`.

The built image exists and runs, independently confirming a successful build:
`event-checkin-api:release-final`, image ID
`sha256:f7ae028dbe70e47c48146a7c1b5dff9785f0bfa7a8005dc4255c78ef14eb2b24`.
The original build command is reported above/by the handover; its terminal build
log is unavailable. No image rebuild was necessary for documentation changes.
`alembic heads` and `alembic current` inside the original container both report
`0013_privacy_notice_workflow (head)` for the existing disposable probe database.
The prior empty-database downgrade/upgrade result was not repeated.

### Container ingress investigation

The original `event-checkin-release-final-probe` on `127.0.0.1:18002` runs
`APP_ENV=test`, with no configured platform host. Its Caddy proxy forwards a
client IP, while test/local mode explicitly rejects forwarded client addresses.
That environment mismatch explains `UNRECOGNIZED_HOST`: the middleware uses
that code for both authority and client-address rejection. It occurs before
tenant-domain resolution. Production mode also rejects a port-bearing public
Host, so using the localhost endpoint as the public authority is inappropriate.
No hostname or tenant-isolation rules were changed.

Fresh original-container probes:

- `/health`: 200, `{"status":"ok"}`.
- `/ready`: 200; API/database ready, worker `not_configured`.
- Direct unauthenticated `/api/v1/auth/csrf`: 404 at Caddy.
- Malformed unauthenticated Brevo POST (`{`): 401 `WEBHOOK_AUTH_INVALID`.
- Trusted-edge request using a localhost public authority: 421
  `UNRECOGNIZED_HOST`, an expected boundary rejection.

A separate same-image container,
`event-checkin-release-production-authority-probe` on `127.0.0.1:18004`, uses
`APP_ENV=production`, `PLATFORM_HOST=platform.release.example.test`,
`FALLBACK_DOMAIN_SUFFIX=release.example.test`, the original Docker network and
synthetic origin secret, and database `sslmode=verify-full`:

- `/health`: 200.
- Authenticated edge `/api/v1/auth/csrf`: 200; token deliberately not recorded.
- `/api/v1/auth/session`: 421 `TENANT_CONTEXT_REQUIRED`, proving the shared host
  still requires signed organization context.
- Injected `Forwarded` and `X-Forwarded-Host` are stripped by Caddy; the preceding
  authorized CSRF request succeeds despite them.
- Malformed unauthenticated Brevo POST: 401 `WEBHOOK_AUTH_INVALID`.
- All checked responses omit the Server header.
- `/ready`: 503, API ready/database unavailable. Direct connection diagnosis:
  local PostgreSQL does not support SSL, but SSL was required. This is a real
  local database transport limitation, not an authority rejection or evidence
  that Supabase readiness passes. TLS verification was not weakened.

An intermediate `event-checkin-release-authorized-probe` on `127.0.0.1:18003`
retains test mode and the default Docker network; it is not readiness evidence
because it lacks the original database network and retains the forwarded-IP
mismatch. All probe containers and the disposable database remain preserved.
No production credentials were changed or recorded.

### Final source and artifact review

`git diff --check` passes for the release diff. Reviewed environment examples,
Render topology, Caddy forwarding, Vercel proxy and runtime configuration:
credentials are replacement placeholders or synthetic local values; populated
local environment files are not staged. No secrets were identified in this
review; this is not a claim of exhaustive automated secret scanning.

The screenshot fixture is committed in `7771e34`: it explicitly mocks the
organization directory and waits for its empty state before capture. The
surviving Playwright last-run record passes. The two pre-existing modified
screenshots are preserved in the final commit; both retain their dimensions,
and the organizer capture retains the Quiet Operations layout. The reports
capture differs only within a small header region. No UI source changes were
made during handover. Platform overview still uses live readiness plus explicit
unavailable aggregate states, with no synthetic platform statistics restored.
The local node_modules symlink is preserved and explicitly ignored so it cannot
be accidentally committed.

### Deployment approval handoff

Follow `PRODUCTION_DEPLOYMENT_PLAN.md`, `PRODUCTION_ENVIRONMENT_CHECKLIST.md`,
`PRODUCTION_SMOKE_TESTS.md` and `ROLLBACK_AND_RECOVERY.md` at this commit:

1. Obtain regions/DPA/cost/domain approvals and missing CI evidence; complete
   the Supabase timed restore test and five-device venue rehearsal.
2. Supabase: provision the approved project, obtain its CA, create distinct
   NOBYPASSRLS logins using `ops/deploy/supabase_roles.sql.example`, take a restore
   point, and run `ops/deploy/migrate.sh` once with the migration-owner URL.
   Verify single head `0013_privacy_notice_workflow`, FORCE RLS and role grants.
   Use verified TLS and direct/session-pooler connections.
3. Render: replace every `REQUIRES_*` Blueprint value, create role-specific
   secret groups and CA/password-corpus secret files, provision private Redis,
   and manually deploy the API, two workers, one dispatcher and health cron at
   the approved release SHA. Keep auto-deploy off. Verify `/ready` 200 over TLS
   and independently verify worker/dispatcher/queue health.
4. Brevo: verify sender/domain, approve quota, install a restricted server-side
   API key and callback Bearer token, subscribe the Render-origin callback to
   delivery/bounce/error events, and test one authorized synthetic inbox.
5. Vercel: import `frontend`, build with `npm run build`, publish `dist`, set
   encrypted server-only `RENDER_API_ORIGIN` and matching `ORIGIN_AUTH_SECRET`,
   then manually deploy the same approved SHA. Attach approved public domains;
   configure matching PLATFORM_HOST/fallback zone on Render.
6. Verify DNS/TLS, cookies, Host/Origin rejection, direct-origin 404, webhook
   401, cross-tenant isolation and synthetic lifecycle smoke tests. Use the
   Render origin for `/health`; public `/ready` is proxied by Vercel. Obtain
   engineering, operations, privacy and incident-owner approval before opening
   registration/import or ticket sending.

Local verification is complete within the evidence limits above. Production
verification, TLS database readiness, external provider configuration, complete
CI evidence, restore rehearsal and venue approval remain incomplete.

## Migration permission correction — 2026-10-28

This follow-up intentionally changes the previously committed upgrade bodies in
`0006_tenant_provisioning.py` and `0008_tenant_branding.py`. Revision IDs,
dependencies, downgrade bodies, RLS policies, role memberships and function
bodies are unchanged. Already-applied revisions are not replayed automatically.

### Confirmed transaction failure

`alembic/env.py` runs an upgrade invocation in a single PostgreSQL transaction.
A committed preflight CREATE grant can be true before a fresh upgrade, while
`0002` revokes it inside that transaction. Original `0006` does not restore it.
Its existing active-domain function is already resolver-owned, so assigning the
same owner does not expose the missing target-schema permission. Transferring
the newly created auth-domain function does, producing SQLSTATE 42501 at
`ALTER FUNCTION resolve_auth_tenant_domain(citext) OWNER TO
 eventcheckin_domain_resolver`. Rollback restores the preflight grant, explaining
why an independent check after failure sees CREATE=true again.

This exact sequence was reproduced locally on PostgreSQL 17 with a restricted
NOSUPERUSER/NOBYPASSRLS migration login and SET/INHERIT membership in the three
function-owner roles. The trace verified CREATE=true before upgrade,
CREATE=false immediately after the 0002 revoke, the exact failing 0006 statement,
and CREATE=true after rollback. It is a confirmed mechanism matching the
reported production symptoms; no production database inspection was performed.
If production had already committed 0005 before the failing invocation, this
specific 0002-in-the-same-transaction explanation would not apply.

### Correction and validation

0006 now grants CREATE to the domain resolver immediately before replacing the
active-domain function, retains it through both ownership transfers, and revokes
it immediately after the auth-domain transfer. 0008 grants/revokes CREATE around
its profile function creation/ownership transfer. 0012 already uses the correct
grant/transfer/revoke sequence and is unchanged. No superuser/BYPASSRLS grants,
policy changes or lasting schema CREATE rights were introduced.

Two new real-PostgreSQL regressions cover a fresh transaction and an upgrade from
committed 0005, both using a restricted migration login. They verify head 0013,
the five restricted function owners, revoked schema CREATE for all three owner
roles, NOLOGIN/NOSUPERUSER/NOBYPASSRLS attributes, and FORCE RLS on representative
tenant tables. Both passed.

The targeted migration harness, tenant isolation, branding, privacy and shared
onboarding run produced 15 passes and one fixture failure: the disposable
cluster lacked the pre-existing `eventcheckin` role expected by an isolation
test. Supplying that NOLOGIN/NOBYPASSRLS fixture role locally and rerunning only
the failed test passed. Total: all 16 selected tests passed across the initial
run and targeted rerun. Ruff and `git diff --check` also passed.

The production image is rebuilt only after this validation, under
`event-checkin-api:migration-permissions-final`. No production connection,
migration, external deployment or push is part of this correction.

The production Dockerfile includes Alembic but does not include
`ops/deploy/migrate.sh`. With an approved, operator-managed environment file
containing production APP_ENV and a migration-owner DATABASE_URL, the image
command is:

```sh
docker run --rm --env-file /secure/eventcheckin-migration.env \
  --mount type=bind,src=/secure/supabase-ca.crt,dst=/etc/secrets/supabase-ca.crt,readonly \
  --entrypoint alembic event-checkin-api:migration-permissions-final upgrade head
```

The file must set DATABASE_URL (not only MIGRATION_DATABASE_URL), use
sslmode=verify-full with sslrootcert=/etc/secrets/supabase-ca.crt, and retain the
required function-owner memberships. The command is supplied for review only;
it was not run against production. Do not log or commit the populated env file.

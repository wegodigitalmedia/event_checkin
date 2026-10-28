# Production deployment plan

**Release:** Event Check-in v1 / Reverb 5.0
**Status:** prepared, not deployed
**Approved providers:** GitHub, Vercel, Render, Supabase PostgreSQL, Brevo

## Production topology

```text
Browser + assigned Vercel HTTPS host (custom/wildcard domains optional)
  -> Vercel static Vite application
  -> same-origin Vercel Functions (/api/* and /ready)
       strict header allowlist + origin-auth secret + public Host/client IP
  -> Render API origin (Uvicorn on 0.0.0.0:$PORT)
       /ready and Brevo callback are explicit exceptions
       outer ASGI middleware requires the Vercel-to-Render secret
       and reconstructs authority/client IP only from its authenticated envelope
       Uvicorn proxy-header processing remains disabled
  -> Supabase PostgreSQL using distinct NOBYPASSRLS login roles

Render background services:
  two Celery workers -> Redis queue -> tenant runtime + jobs roles
  one outbox dispatcher -> dispatcher role + Redis
  five-minute job-health cron -> operator role, logs aggregate queue indicators

Brevo:
  durable ticket delivery intents/jobs -> transactional email API
  authenticated delivery webhook -> Render API -> tenant-scoped delivery state
```

Vercel builds `frontend` with `npm run build` and publishes `dist`. The
configuration is [frontend/vercel.json](../frontend/vercel.json). Server-only
variables are shown in `frontend/.env.production.example`; never prefix them
with `VITE_`.

Render builds [Dockerfile.api](../ops/deploy/Dockerfile.api). The API starts Uvicorn directly; Render terminates HTTPS. The outer application
middleware authenticates `ORIGIN_AUTH_SECRET` before accepting public host/client
headers from Vercel. It removes untrusted proxy headers and the private envelope.
Render proxy IPs need not be enumerated; leave `INGRESS_PROXY_IPS` unset for this
topology. The example Blueprint is
[render.production.yaml.example](../ops/deploy/render.production.yaml.example).
It deliberately contains invalid `REQUIRES_*` values and has automatic deploys
disabled. Approve region, plan, domains, and cost before creating resources.

## Deployment order and release gates

1. **Provision infrastructure.** Create the Vercel project from `frontend`,
   Render API/worker/dispatcher/cron and private Redis, the Supabase production
   project, Brevo account/sender, DNS records, and provider alert channels.
   Select regions only after privacy and latency approval.
2. **Configure database roles and connectivity.** Download the Supabase CA,
   create independent login roles with
   [supabase_roles.sql.example](../ops/deploy/supabase_roles.sql.example), and
   grant only the existing NOLOGIN role memberships. Every application login
   must report `rolbypassrls=false` and `rolsuper=false`. Use direct or session
   pooler connections for long-lived SQLAlchemy processes. Do not use a
   transaction-pooler URL for migrations or session-state/RLS verification.
   Require TLS hostname verification (`sslmode=verify-full`).
3. **Run controlled migrations.** Take a named restore point/PITR marker and a
   schema-only dump. Build the exact release image, run `alembic heads` and
   `alembic current`, then execute `ops/deploy/migrate.sh` once with the
   migration-owner URL. Expected single head: `0013_privacy_notice_workflow`.
   Re-run `alembic current`, FORCE RLS and role-grant checks. Never expose the
   migration owner to an API or worker.
4. **Deploy backend and workers.** Manually deploy the same Git commit to the
   Render API, dispatcher, Celery workers and job-health cron. Supply only each
   process's role credentials. Mount the approved password corpus and Supabase
   CA as secret files. The storage-maintenance process is intentionally absent:
   it is restricted to local/test synthetic artifacts.
5. **Verify readiness.** Render must receive `2xx` from `/ready`; verify API and
   database checks, graceful SIGTERM behavior, Redis connectivity, dispatcher
   publishing and worker job consumption. `/ready` currently reports worker as
   `not_configured`; worker health is independently asserted from Render process
   state and `python -m app.worker.ops health`.
6. **Configure transactional email.** Verify the Brevo sending domain and
   sender, create a restricted API key, configure the callback URL
   `https://RENDER_ORIGIN/api/v1/webhooks/brevo`, and set its Bearer token.
   Subscribe to delivered, soft/hard bounce, invalid, blocked, spam and error.
   Confirm account quota/rate limits exceed the planned send schedule. Test
   with one synthetic address before allowing a bounded synthetic batch.
7. **Deploy frontend.** Manually deploy the same Git commit from `frontend` to
   Vercel. Set `RENDER_API_ORIGIN` and `ORIGIN_AUTH_SECRET` as encrypted
   server-side values. Verify that neither appears in browser assets or source
   maps. Build output is `dist`.
8. **Configure HTTPS, domains, cookies and CORS.** Use the assigned Vercel platform hostname and Render `onrender.com` origin
   in shared-host mode. Leave `FALLBACK_DOMAIN_SUFFIX` unset; custom/wildcard
   tenant domains require a separately approved owned zone. Custom origin
   domains and disabling the assigned Render hostname are optional later steps. The public host reaches
   the backend only through the same-origin Vercel proxy, so no cross-origin
   browser CORS allowance is required. Confirm Secure, HttpOnly, host-only,
   SameSite=Strict cookies and exact Origin/Host enforcement.
9. **Execute synthetic production smoke tests.** Follow
   [PRODUCTION_SMOKE_TESTS.md](PRODUCTION_SMOKE_TESTS.md). Do not use real
   participant data, bulk mail, or destructive load. Record request IDs and
   redact credentials, cookies, QR contents and attendee fields.
10. **Obtain release approval.** The engineering lead, event operations owner,
    privacy owner and incident commander review evidence and open risks. Enable
    attendee registration/import and ticket sending only after approval.

## Runtime and shutdown requirements

- API startup: `start-api` (`exec uvicorn app.main:app --host 0.0.0.0
  --port "${PORT:-10000}" --no-proxy-headers --no-server-header`).
  Leave the Render Docker Command override empty (or use `start-api`).
  Keep the health check at `/ready`; `/health` is a public liveness probe.
- Worker: `celery -A app.worker.celery_app:celery_app worker --loglevel=INFO
  --concurrency=4`; two instances in the example. Confirm Brevo quota before
  increasing concurrency.
- Dispatcher: `python -m app.worker.dispatcher`; run exactly one normally.
- API shutdown allowance: 60 seconds. Worker allowance: 120 seconds. Jobs use
  late acknowledgement, database leases and idempotency; a terminated worker's
  job is retried.
- Logs are structured JSON with request ID, method, route, status and duration.
  Scanner logs include only outcome/reason code, never the credential.

## Monitoring and alerts

Use provider monitoring rather than a custom telemetry dashboard for v1.

| Signal | Source | Initial action threshold |
|---|---|---|
| API availability/database | Render `/ready` + external HTTPS probe | page after two consecutive failures |
| API 5xx/error rate | Render structured logs/metrics | investigate sustained >1% over 5 min |
| Response and scan latency | Render/Vercel request metrics | page if scan p95 breaches rehearsal SLO |
| Worker/dispatcher health | Render process events | page on restart loop or stopped instance |
| Queue/outbox backlog | job-health cron aggregate JSON | page on dead jobs or oldest unpublished >60 s |
| PostgreSQL connections/CPU/locks/storage | Supabase dashboard/alerts | warn at 70%, page at approved critical limit |
| Email failures | Brevo webhook state + dashboard | page on bounce/error spike or sustained deferred mail |
| Admission failures | structured `reason_code` logs | alert on unexpected invalid/revoked/context spike |

Thresholds are starting points, not measured event baselines. Final latency and
volume thresholds must come from the five-gate venue rehearsal.

## External approvals still required

- Production regions, DPA/data residency, service plans and spend.
- Public and origin domain names and DNS change window.
- Supabase PITR/backup retention and a timed restore rehearsal.
- Brevo sender/domain verification, quota, rate limit and webhook creation.
- Password corpus source/version and secret-file delivery.
- Event schedule, gates, privacy notice text/basis/approval reference, event-day
  support roster and connectivity fallback.

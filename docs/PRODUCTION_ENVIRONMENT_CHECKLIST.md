# Production environment checklist

No value in this file is a credential. Populate provider secret stores, not a
repository `.env` file. Start from `.env.production.example` and
`frontend/.env.production.example`.

## GitHub and release

- [ ] Protected release commit reviewed; CI checks pass on that exact SHA.
- [ ] No untracked files or generated test artifacts in the release worktree.
- [ ] Secret scan completed; no `.env`, database dump, populated race config or
      provider key is committed.
- [ ] Main remains unchanged until explicit merge authorization.

## Supabase PostgreSQL

- [ ] Region, PostgreSQL version, DPA and retention approved.
- [ ] PITR/backup enabled; restore target and restore owner documented.
- [ ] Required extensions from migrations are available (`citext`, `pgcrypto`).
- [ ] Supabase CA mounted and every URL uses `sslmode=verify-full`.
- [ ] Migration owner is release-only and absent from Render runtime settings.
- [ ] Distinct login roles exist for runtime, identity, platform, jobs,
      dispatcher, operator, bootstrap, domain worker and domain scheduler.
- [ ] Every login is `NOSUPERUSER NOBYPASSRLS`; normal API uses runtime,
      identity and platform roles only.
- [ ] `alembic heads` and `alembic current` both identify the single expected
      head `0013_privacy_notice_workflow` after deployment.
- [ ] Tenant tables report both `relrowsecurity=true` and
      `relforcerowsecurity=true`; cross-tenant probes return no rows.
- [ ] Direct/session-pooler connection capacity covers API + workers with
      headroom; transaction pooling is not used where session state is required.

## Render API and background services

- [ ] Approved region and plans replace every `REQUIRES_*` value.
- [ ] API origin domain attached; default Render subdomain disabled.
- [ ] `ORIGIN_AUTH_SECRET` is random, shared only with Vercel and rotated via a
      coordinated maintenance procedure.
- [ ] Uvicorn binds `0.0.0.0:$PORT` with `--no-proxy-headers`; application
  middleware authenticates the Vercel origin envelope. `INGRESS_PROXY_IPS` is
  unnecessary for the direct Render path. Clear stale Docker Command overrides.
- [ ] Auth key, ticket keyring, registration HMAC and webhook token are
      independently generated and backed up according to policy.
- [ ] Password corpus file and SHA-256 are mounted and verified at startup.
- [ ] Redis uses TLS/private access, persistence/no-eviction and alerts.
- [ ] Private S3-compatible storage, lifecycle and credentials are approved if
      branding upload is enabled.
- [ ] API `/health` and `/ready` pass; two API instances and two workers are
      healthy; dispatcher has exactly the intended instance count.
- [ ] SIGTERM rehearsal completes inside API/worker shutdown allowances.
- [ ] Structured logs do not contain cookies, CSRF tokens, QR credentials,
      attendee data, API keys or database URLs.

## Vercel frontend

- [ ] Project root is `frontend`; build command `npm run build`; output `dist`.
- [ ] `vercel.json` rewrites `/reset`, `/invite`, `/ready`; `/api/*` maps to the
      catch-all Function.
- [ ] `RENDER_API_ORIGIN` is HTTPS and points to the gated Render origin.
- [ ] `ORIGIN_AUTH_SECRET` is encrypted and not exposed as a `VITE_*` variable.
- [ ] Platform and approved tenant/wildcard domains are attached with valid TLS.
- [ ] CSP, nosniff, no-referrer, permissions and immutable asset headers verified.
- [ ] SPA routes refresh successfully; API responses and `Set-Cookie` survive
      the same-origin proxy; request bodies above 12 MiB fail closed.

## Brevo

- [ ] Sending domain and `EMAIL_FROM` identity verified; SPF/DKIM/DMARC reviewed.
- [ ] Restricted `BREVO_API_KEY` stored only on API/worker services.
- [ ] Random `BREVO_WEBHOOK_TOKEN` stored on API and configured as callback
      Bearer authentication.
- [ ] Transactional webhook points directly to the Render callback path and is
      subscribed to delivered, bounce, invalid, blocked, spam and error events.
- [ ] Quota/rate limit supports planned batch; worker concurrency/send schedule
      stays below it.
- [ ] Synthetic single-message test confirms QR attachment, provider message ID,
      delivery callback and durable `delivered` state.
- [ ] Retry/idempotency and bounce/error alerts are verified without bulk mail.

## Reverb 5.0 release data

- [ ] Organization created and organizer invitation accepted.
- [ ] Exact privacy notice drafted, externally approved and activated; actor,
      timestamps, version and approval reference recorded.
- [ ] Event schedule/timezone/check-in window and gates reviewed by two operators.
- [ ] Synthetic import completes before real import; authorization checkbox and
      row-error workflow verified.
- [ ] Real participant import has a named data owner and retention procedure.
- [ ] Five devices, chargers, network paths and gate assignments rehearsed.
- [ ] Incident commander, support channel and stop/go authority named.

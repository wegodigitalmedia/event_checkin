# M2-01 local operations and recovery

## Prerequisites

Use distinct runtime, identity, platform-control, bootstrap, migration-owner, and worker database credentials. `ops/local_roles.sql` provisions only local development roles. Set `PLATFORM_HOST`, `PLATFORM_DATABASE_URL`, `IDENTITY_DATABASE_URL`, and `AUTH_ENCRYPTION_KEY`. In shared-host mode use the assigned Vercel hostname (currently `event-checkin-console.vercel.app`) and leave `FALLBACK_DOMAIN_SUFFIX` unset. Organizations and privacy administration use the restricted platform connection without DNS records. The domain-management service remains unavailable. Set `FALLBACK_DOMAIN_SUFFIX` only when enabling a separately approved owned DNS zone; the platform host must belong to that zone. Set `BOOTSTRAP_DATABASE_URL` only for the one-time operator command; remove it from the API environment after bootstrap. The bootstrap operator must have a reviewed email-control record or an explicitly approved mailbox-verification waiver, an attributable operator reference, and a dated grant expiry. Password screening requires either an approved, versioned compromised-password corpus or the explicit bootstrap-only HIBP online option described below. Local fixture mode is enabled only in local/test environments; staging and production default to a disabled provider.

Apply Alembic revision `0006_tenant_provisioning` using the migration owner. The migration reserves existing domain rows; it does not promote old records to active. Keep the M1-02 owner/runtime separation and FORCE RLS. Bootstrap with an interactive terminal:

```sh
python -m app.tenancy.bootstrap --email operator@example.test \
  --operator-ref CHANGE-RECORD --email-verification-ref VERIFICATION-RECORD \
  --grant-until 2026-11-01T00:00:00Z
```

The command consumes a database-enforced singleton through a restricted function; concurrent attempts cannot create a second actor. The bootstrap login has no direct table-write grants or HTTP equivalent. Its SQL connection hides bound parameters in error output. Keep its credential outside the API, workers, and routine operator environments. Further platform grants require a separate reviewed contract. Platform sign-in completes TOTP enrollment before any provisioning operation. Rotate or revoke a compromised grant through a reviewed operator process; a database trigger revokes existing platform sessions when a grant changes.

## Bootstrap without a bulk corpus

An operator may explicitly choose `--password-check hibp` for the one-time CLI.
It performs a TLS-verified request to `api.pwnedpasswords.com`, sends only the first
five hexadecimal characters of the password SHA-1 digest, requests padded results,
and compares the remaining hash locally. It never sends the password or full hash.
There are no redirects, fallback to unchecked passwords, or database connections
before screening succeeds. Timeout, non-200, oversized, and malformed responses
stop bootstrap. Network egress to that HTTPS endpoint is required. Offline screening
remains the default; API invitation and password-reset screening remain unchanged.

For an explicitly approved mailbox-verification exception, replace
`--email-verification-ref` with `--waive-mailbox-verification`. The options are
mutually exclusive. The existing singleton and security audit metadata record
`WAIVED_BY_OPERATOR:<operator-ref>` in `email_verification_ref`; this is an exception
record, not evidence of verified email. No migrations or existing revisions change.

Approved preparation for BOOTSTRAP-20261028-01: intended administrator
`wegodigitalmedia@gmail.com`, expiry `2026-11-30T23:59:59Z`, mailbox verification
waived by operator instruction. MAILBOX-20261028-01 is not claimed as completed.
Account creation still requires a separate explicit production execution approval.

Build locally from the repository root containing this change:

```sh
docker build -f ops/deploy/Dockerfile.api -t event-checkin-api:bootstrap-hibp-final .
```

After execution approval, run from a trusted interactive terminal, replacing only
the `/secure/` host paths with the actual private files:

```sh
docker run --rm -it \
  --env-file /secure/eventcheckin-bootstrap.env \
  --mount type=bind,src=/secure/supabase-ca.crt,dst=/etc/secrets/supabase-ca.crt,readonly \
  --entrypoint python event-checkin-api:bootstrap-hibp-final \
  -m app.tenancy.bootstrap \
  --email wegodigitalmedia@gmail.com \
  --operator-ref BOOTSTRAP-20261028-01 \
  --waive-mailbox-verification \
  --password-check hibp \
  --grant-until 2026-11-30T23:59:59Z
```

The private env file must provide `APP_ENV=production`, a valid runtime
`DATABASE_URL` (required by settings), and restricted `BOOTSTRAP_DATABASE_URL`.
Both database URLs must use `sslmode=verify-full` and the mounted CA path.
Shared-pooler usernames include `.<PROJECT_REF>`; retain each role's own password.
No corpus configuration is required for this CLI mode. Do not include the bootstrap
credential in Render's routine API environment. Never put passwords in arguments,
Git, or chat. The CLI prompts for the new account password twice. After success,
sign in on the platform host, complete mandatory TOTP enrollment, and store recovery
codes privately. Do not retry after ambiguous database outcomes until checking the
singleton read-only. The grant expires at the approved timestamp; renewal requires
a separately reviewed grant procedure.

## Provision and verify

On the dedicated platform host, create a tenant. The result reserves a platform-owned fallback hostname and one-time DNS TXT proof. Configure the proof, certificate, edge mapping, and routing smoke check with the local fixture adapter or a future G-06-approved provider. Request a check, inspect the independent ownership/TLS/routing results, and activate only after all checks pass. The initial claim deadline is 48 hours; once a domain has been activated, reconciliation still requires the DNS proof to remain present and refreshes ownership evidence. An active domain whose evidence expires fails closed at request resolution even before the next reconciliation.

Run the scheduler as `python -m app.tenancy.maintenance` with `DOMAIN_SCHEDULER_DATABASE_URL`. The domain worker uses `DOMAIN_WORKER_DATABASE_URL`; neither receives the platform-control credential. The scheduler creates durable PostgreSQL jobs and outbox events; the M1-04 dispatcher and worker perform checks. Queue outages do not commit an authoritative route change. If a worker crashes, the existing lease/retry machinery recovers the job. The reconciler locks the current domain row, compares the claim digest and observation order, and records safe error codes. Ownership, TLS, and smoke evidence expire independently; the smoke check must be less than 15 minutes old for routing. Reconciliation runs every five minutes while healthy, so a prolonged outage fails closed.

If an unactivated claim expires, the authorized owner or platform actor can renew it. This rotates the proof and returns the new TXT value once; the old proof cannot validate the new claim. Active routes cannot rotate proofs without controlled deactivation.

An expired, unverified claim still reserves its globally unique hostname. M2-01 has no cross-tenant claim release or transfer operation. A disputed or abandoned claim needs an approved operator policy before reassignment; do not edit the hostname or delete its audit history ad hoc. This prevents silent takeover but can temporarily block the rightful claimant.

After the fallback is active, issue the first-owner invitation to a verified address through the approved local delivery adapter. The owner accepts on the fallback host and completes mandatory MFA before membership becomes active. Production invitation delivery remains disabled until its provider is approved. If delivery reports failure after the invitation is committed, the exact token is revoked and the failure is audited; it is never logged or revealed. The platform actor can then issue a replacement. If delivery reported success but the recipient did not receive the link, use the platform reissue action: it revokes the pending invitation and sends one new 48-hour link to the same address. The old link cannot be accepted. A database outage during failure compensation requires an operator to inspect/revoke the outstanding invitation before another attempt.

Tenant owners/admins may request custom claims. A platform actor performs final activation. A custom primary can be deactivated only while the fallback is eligible; the fallback becomes primary. Certificate or ownership loss deactivates the affected custom route on reconciliation. Suspended tenants lose ordinary routing; only the fallback host and owner recovery permission remain. Closed tenants have no normal route.

## Failure and incident checks

- Unknown, duplicate, invalid, or untrusted-proxy Host authorities return 421. The edge must validate SNI/Host, strip forwarded authority headers, and restrict direct origin access to configured ingress peers. Uvicorn runs without proxy-header processing.
- A dangling DNS record alone cannot activate a route. Proof, valid TLS, edge mapping, smoke check, and platform approval are all required.
- Domain IDs and tenant IDs in platform URLs are checked against the MFA actor's current grant. Tenant domain URLs use server-resolved tenant membership and composite foreign keys.
- Keep `PLATFORM_DATABASE_URL` away from workers and the bootstrap credential away from the API process. The domain worker and scheduler use dedicated roles; none of these restricted roles has participant-table access or `BYPASSRLS`.
- Inspect domain error codes, `next_reconcile_at`, job state, and audit events during recovery. Never copy raw invitation tokens, challenge cookies, TOTP keys, or private user data into logs or job payloads.

M2-01 cannot be marked complete until G-06 approves production/staging edge, certificate provider, owned staging hostname, and region, and a real HTTPS staging-domain ownership, issuance, activation, failure and recovery exercise passes.

The `0006` downgrade is exercised only on an isolated, empty test database. Once initial-owner invitations or other M2-01 records exist, rollback needs a separate data migration and operator review. Local fixture DNS/TLS/smoke observations do not demonstrate production certificate issuance or real edge routing.

## Bootstrap simplification validation (2026-10-28)

- 21 focused bootstrap/password-security tests passed on the host and in the
  Python 3.13 image with network disabled and synthetic fixtures only.
- Ruff passed; strict mypy passed for all 66 application modules.
- Production Dockerfile built `event-checkin-api:bootstrap-hibp-final`; CLI help
  verified without network access. A separate live HIBP request correctly rejected
  a known synthetic compromised password, without database credentials.
- The optional broader host suite was interrupted after it stalled; it is not
  claimed as passed. No production database tests, bootstrap, push, or deployment
  were performed for this change.

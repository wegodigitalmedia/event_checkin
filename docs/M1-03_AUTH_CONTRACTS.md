# M1-03 staff identity contracts

**Authority:** [G-02](DECISIONS/G-02_STAFF_IDENTITY.md) and the product-owner addendum. This document describes the implementation contract; provider activation and a password dataset remain open.

## Identity and database boundaries

- `eventcheckin_identity_app` inherits a limited `eventcheckin_identity` role. It can read global identities and session records, plus tenant memberships, invitations and assignments subject to FORCE RLS. It has neither table ownership nor `BYPASSRLS`.
- `eventcheckin_app` remains the tenant-data runtime login. Its connection is opened for protected tenant work only after the identity service verifies the session, active membership and effective permission. `authorized_tenant_session` sets `app.tenant_id` for that transaction only.
- A verified active hostname resolves a tenant but does not authorize a person. The identity connection sets a limited transaction context to inspect membership; it cannot read registrations or check-ins. A session token is bound to its tenant. Opening a second tenant's domain requires a fresh session on that host, and membership is checked there.
- `password_credentials`, `auth_sessions`, `auth_challenges`, `password_reset_tokens`, `totp_credentials`, `mfa_recovery_codes`, `platform_grants`, `security_audit_events` and `auth_rate_limits` are global identity tables restricted to the identity role. `staff_invitations` and `event_assignments` are tenant-owned with FORCE RLS and composite foreign keys.
- The migration role owns DDL. The identity and tenant runtime logins cannot own protected tables. M1-03 uses revisions `0003_staff_identity` and `0004_auth_session_invalidation`; isolated downgrade returns to `0002_tenant_foundation`. Revision `0004` revokes sessions and pending MFA challenges in the same transaction when a user status or tenant membership status/role changes, including changes made outside the API. It also removes M1-02's broad membership write grant from the tenant-data runtime role; the identity role remains the sole application writer. Downgrading populated auth data destroys credentials and sessions and requires a reviewed data plan.

## Browser API

All paths are under `/api/v1/auth`. JSON mutations require `X-CSRF-Token` from `GET /csrf`; the CSRF cookie and session cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, host-only, and scoped to `/`. API responses must use `Cache-Control: no-store` at the serving edge. Authentication errors use an object with `code` and safe `message` in FastAPI's `detail` field.

| Method and path | Request | Successful response |
|---|---|---|
| `GET /csrf` | None | `{csrf_token}` and CSRF cookie |
| `POST /login` | `{email,password}` | `{state:"session"|"mfa"|"enroll"}` and a session or narrow challenge cookie |
| `POST /logout` | CSRF header | `{state:"logged_out"}`; session revoked and cookie cleared |
| `GET /session` | Session cookie | User ID, email, tenant ID, role, absolute expiry; 401 when expired/revoked |
| `POST /mfa/enroll` | Challenge cookie and CSRF | TOTP setup secret, algorithm, digits, period; only in enrollment challenge |
| `POST /mfa/verify` | `{code,recovery?}` | Full session and initial single-use recovery codes only on enrollment |
| `POST /password-reset/request` | `{email}` | Same generic message for eligible/ineligible addresses |
| `POST /password-reset/complete` | `{token,password}` | `{state:"password_changed"}`; all existing sessions revoked |
| `POST /invitations` | `{email,role,event_id?,gate_id?}` and authorized admin session | `{state:"invitation_requested"}` |
| `POST /invitations/accept` | `{token,password}` | Full scanner session or narrow MFA challenge |
| `POST /memberships/{user_id}/revoke` | Authorized tenant owner/admin session | Membership and affected tenant sessions revoked; `{state:"revoked"}` |

Invitation and reset tokens are sent through the email adapter after database commit, never returned by the API or logged. Staff email inputs and the local SMTP adapter accept one mailbox only; address lists and display-name forms are rejected so one secret link cannot be delivered to multiple recipients. Links put the token in the URL fragment, which is not sent to the HTTP server; the browser removes it from the address bar and submits it in the protected request body. An existing user accepting a new tenant invitation supplies their current password. New passwords require a configured, SHA-256-pinned offline SHA-1 digest corpus. Missing or invalid corpus blocks new credential creation and password reset with 503. No corpus is approved for production by this implementation.

Reset completion is throttled by the verified tenant and requester IP. It verifies an unexpired, unused token and active identity before running the password-corpus check or Argon2id hashing. Completing one reset consumes all outstanding reset links for the same user.

## Effective permissions

The server-side matrix is implemented in `app/auth/policy.py`. Tenant owner/admin may manage tenant settings, staff/invitations, events/gates, check-in, reporting, attendee exports and billing. Organizer/manager permissions require an active event assignment and exclude tenant-wide staff, billing and security settings. Gate supervisor permissions require a matching assigned gate, exclude exports, and cover gate operations and assigned-gate reporting. Gate scanner has assigned-gate check-in only. Legacy `gate_staff` is restricted to scanner permissions. Platform and support grants are separate records; there is no implicit tenant access or RLS bypass. No platform/support operation is exposed by M1-03.

Privileged effective permissions require confirmed TOTP. The scanner role can have an opaque session without MFA. Session idle and absolute limits follow G-02. Permission and membership are rechecked on protected requests. Successful sign-in revokes the previous session cookie. User suspension and tenant membership status/role changes revoke affected sessions in the database transaction. Future grant administration APIs must likewise revoke affected sessions.

## Local setup and activation gates

1. Run `docker compose up --build -d` and `docker compose run --rm migrate`; do not delete the existing volume. Mailpit's local inbox is at `http://127.0.0.1:8025`.
2. Generate a local encryption key outside the repository: `openssl rand -base64 32`. Export it as `AUTH_ENCRYPTION_KEY` before Compose starts. Rotate with a reviewed key-reencryption procedure; `AUTH_KEY_ID` identifies the active key.
3. Supply a separately approved versioned corpus path and whole-file SHA-256 through `COMPROMISED_PASSWORD_CORPUS` and `COMPROMISED_PASSWORD_SHA256`. In a container, mount the file read-only at the configured path. Until supplied, invitation acceptance for new users and password reset completion intentionally fail closed.
4. For host development, set `IDENTITY_DATABASE_URL` to the local identity login in `.env.local.example`; use `DATABASE_URL` for the restricted tenant runtime login. Do not use the migration owner in the API process.
5. Trusted M2 tenant provisioning will establish the first-owner invitation path. Verifying a custom domain and distributing a production email provider are also outside this milestone. Without a verified domain and a trusted first owner, staff cannot start the invitation flow. Production email stays disabled until provider approval.

PostgreSQL integration tests require `TEST_MIGRATION_DATABASE_URL` for an isolated test cluster with `CREATE DATABASE` and role-creation rights. The test fixture creates and removes its own database and test logins; it does not reset the development database or volume.

## Contract limits requiring follow-up

- M0-02 has not frozen every identity error code or tenant picker contract. A user can access another tenant through its verified hostname and fresh login; cross-domain single sign-on and automatic tenant discovery are not approved.
- Product-owner clarification for this milestone keeps platform/support grants as schema only. Their sign-in, host and operations are deferred until separately approved.
- A maintained, versioned compromised-password dataset and production mail provider still need approval. This is an activation gate, not permission to bypass screening or email delivery.
- MFA recovery after all recovery methods are lost requires a separately reviewed administrative identity-verification runbook. No email-only MFA bypass exists.
- The browser/device support policy for gate operations remains M4 scope. This milestone does not grant attendee identity display or implement check-in.

## Online credential screening option (2026-10-28)

Set `PASSWORD_SCREENING_MODE=hibp` on the backend to use the same TLS-verified,
SHA-1-prefix-only HIBP range check as operator bootstrap for new invitation
passwords and password reset completion. This covers organizer and gate staff
credentials through their common authentication service. Existing-user invitation
acceptance verifies the existing password without re-screening it. Ordinary
platform/staff/gate sign-in, MFA, session validation, QR redemption, and scanning
never call HIBP. Offline screening remains the default; invalid mode values fail
settings validation. HIBP network errors or invalid responses fail closed with
`PASSWORD_SCREENING_UNAVAILABLE` (503); token consumption and credential writes
remain transactional and do not commit after a failed check. No schema changes.

Render: set `PASSWORD_SCREENING_MODE=hibp` and redeploy code containing this change.
No Vercel variables, corpus mount, or HIBP API key is required for this mode.
Allow outbound HTTPS to `api.pwnedpasswords.com`. The existing bootstrap CLI retains
its independent explicit `--password-check hibp` switch. No account passwords,
full hashes, range responses, or authentication tokens are logged by the checker.

Validation: 36 authentication and screening tests passed locally, including real
PostgreSQL invitation, reset replay, and gate access tests; simulated HIBP outage
left invitation acceptance retryable. Ruff and strict mypy (66 modules) passed.
No production database access or deployment performed during validation.

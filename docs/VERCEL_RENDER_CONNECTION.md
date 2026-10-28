# Production Vercel-to-Render connection

Repository: `wegodigitalmedia/event_checkin`, branch `main`.

- Browser origin: `https://event-checkin-phi.vercel.app`
- API origin: `https://event-checkin-backend-1qd3.onrender.com`
- Vercel project root: `frontend`; framework: Vite; build: `npm run build`;
  output: `dist`; Node.js runtime: 22.x (pinned in package.json).

## Environment configuration

Set these in Vercel Project Settings -> Environment Variables, scoped to
**Production**. They are read only by server-side Functions; Vercel may also
make them available during the build, but they must never be imported into
client code or prefixed with VITE_. Redeploy after changing values.

| Variable | Production value |
| --- | --- |
| `RENDER_API_ORIGIN` | `https://event-checkin-backend-1qd3.onrender.com` |
| `ORIGIN_AUTH_SECRET` | The same secret already configured on the Render API; mark sensitive and never print or commit it |

Preview and Development should use separate staging/local configuration and
secrets, not automatically inherit the production origin secret. No browser API
base URL or VITE_* secret variable is required.

On Render, retain APP_ENV=production, the matching ORIGIN_AUTH_SECRET, verified
TLS role-specific database URLs, CA secret file and existing auth/worker keys.
Set PLATFORM_HOST=event-checkin-phi.vercel.app (hostname only). This identifies
the public shared application host, not the Render origin. No purchased domain
is required: leave FALLBACK_DOMAIN_SUFFIX unset in shared-host mode. Platform
identity, organization onboarding/directory and privacy workflows use the
restricted platform connection independently of DNS provisioning. Domain
provisioning, verification and activation stay disabled without an approved
owned fallback zone. Never use vercel.app as that zone. If enabling DNS mode
later, existing namespace validation still requires PLATFORM_HOST to belong to
the configured owned zone. No CORS exception or cookie Domain override is needed.

IDENTITY_DATABASE_URL, AUTH_ENCRYPTION_KEY and the approved password corpus
configuration remain prerequisites for real authentication. Creating database
login roles alone does not configure these API environment variables. The
proxy/CSRF checks do not constitute an authenticated login rehearsal.

## Request and cookie boundary

The explicit internal rewrite sends `/api/:path*` to the named Node Function
`api/render-proxy.js`. The reserved __render_path query parameter carries only
the route; the handler removes it before forwarding the remaining query string.
Ambiguous routing parameters, traversal and malformed paths are rejected.
`/ready`, `/reset`, `/invite`, existing static pages, and security headers remain
configured as before. The old bracket-named catch-all function is replaced.

The Function forwards only approved browser headers, including Cookie, Origin
and X-CSRF-Token, and constructs the private origin-secret/public-host/client-IP
envelope. Render validates the secret before interpreting that public authority.
Host remains the browser-facing Vercel hostname at the application boundary.
Public and tenant authorization checks are unchanged.

All proxy responses use Cache-Control: no-store. Each upstream Set-Cookie is
forwarded individually without changing Domain, Path, Secure, HttpOnly or
SameSite. Backend __Host-* cookies have Path=/ and no Domain, so the browser
binds them to the Vercel response host. Redirects are not followed. The secret
is not present in vercel.json or Vite source, responses, or browser assets.

## Verification

Before this correction, public HTTPS probes showed Vercel `/api/v1/auth/csrf`
returning Vercel NOT_FOUND, `/ready` returning ORIGIN_UNAVAILABLE, Render `/health`
returning 200, and Render `/ready` returning database-unavailable 503. Direct
Render CSRF access correctly returned 404. The operator then confirmed setting
Vercel Production variables and began adding Render PLATFORM_HOST; secret
values were not requested or inspected.

Regression tests cover the named handler's routing/query preservation,
traversal/duplicate rejection, origin/header validation, CSRF and Cookie
forwarding, multiple unchanged host-only cookies, no caching, body limits, and
absence of the synthetic origin secret from responses. A production build with
a synthetic secret sentinel is checked for accidental client-bundle inclusion.
Node 22 validation passed: seven production-proxy tests, one local-proxy test,
two token tests, ESLint, TypeScript and the Vite production build. All built
assets were checked for the synthetic sentinel and server variable names; none
were present. Existing security headers and route entries match the prior
configuration exactly.

Live post-deployment status is recorded in the handoff response; provider
settings and authenticated user sessions cannot be inferred from local tests.

After deployment, GET https://event-checkin-phi.vercel.app/api/v1/auth/csrf must
return JSON with a token and a Secure/HttpOnly/SameSite=Strict __Host-ecs_csrf
cookie, with Path=/ and no Domain. Do not log either value. Confirm the response
URL stays on the Vercel host. GET /ready independently verifies API/database
readiness; /health alone is not a database connectivity check.

Routing/runtime references:

- https://vercel.com/docs/routing/rewrites
- https://vercel.com/docs/functions/runtimes/node-js
- https://vercel.com/docs/headers/request-headers

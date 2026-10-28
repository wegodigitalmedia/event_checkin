"""Authenticate the Vercel-to-origin envelope before interpreting its authority."""

from hmac import compare_digest
from ipaddress import ip_address

from pydantic import SecretStr
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send


class AuthenticatedOriginMiddleware:
    def __init__(self, app: ASGIApp, secret: SecretStr) -> None:
        self.app = app
        self.secret = secret.get_secret_value().encode("utf-8")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in {
            "/health", "/ready", "/api/v1/webhooks/brevo",
        }:
            await self.app(scope, receive, send)
            return
        headers = scope.get("headers", [])
        tokens = [v for k, v in headers if k.lower() == b"x-eventcheckin-origin-auth"]
        if len(tokens) != 1 or not compare_digest(tokens[0], self.secret):
            await Response(status_code=404)(scope, receive, send)
            return
        hosts = [v for k, v in headers if k.lower() == b"x-eventcheckin-public-host"]
        addresses = [v for k, v in headers if k.lower() == b"x-eventcheckin-client-ip"]
        try:
            if len(hosts) != 1 or len(addresses) != 1:
                raise ValueError("A single public authority and client address are required")
            client_ip = str(ip_address(addresses[0].decode("ascii"))).encode("ascii")
        except (ValueError, UnicodeDecodeError):
            await JSONResponse(
                status_code=421,
                content={"detail": {"code": "UNRECOGNIZED_HOST", "message": "Host is unavailable"}},
            )(scope, receive, send)
            return
        # Ignore all proxy-supplied authority/client headers. Only the authenticated
        # envelope supplies Host and one client IP; Origin is preserved for CSRF.
        forwarded = [
            (k, v) for k, v in headers
            if k.lower() not in {b"host", b"forwarded", b"x-real-ip"}
            and not k.lower().startswith((b"x-forwarded-", b"x-eventcheckin-"))
        ]
        forwarded.extend([(b"host", hosts[0]), (b"x-forwarded-for", client_ip)])
        scope = {
            **scope, "headers": forwarded, "scheme": "https",
            "client": (client_ip.decode("ascii"), 0),
            "eventcheckin.authenticated_origin": True,
        }
        await self.app(scope, receive, send)

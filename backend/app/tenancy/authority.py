"""Canonical request authority at the application ingress boundary."""

from ipaddress import ip_address

from fastapi import Request

from app.core.config import Environment, Settings
from app.db.session import TenantResolutionError, normalize_hostname


class AuthorityDenied(ValueError):
    pass


def require_trusted_ingress(request: Request, settings: Settings) -> None:
    if settings.origin_auth_secret is not None:
        if request.scope.get("eventcheckin.authenticated_origin") is not True:
            raise AuthorityDenied("Authenticated origin is required")
        return
    peer = request.scope.get("client")
    allowed = {
        ip_address(item.strip()) for item in settings.ingress_proxy_ips.split(",") if item.strip()
    }
    try:
        if peer is None or ip_address(peer[0]) not in allowed:
            raise AuthorityDenied("Ingress peer is not trusted")
    except ValueError as exc:
        raise AuthorityDenied("Ingress peer is not trusted") from exc


def trusted_client_address(request: Request, settings: Settings) -> str:
    """Use one edge-overwritten client address from an authenticated ingress peer."""
    peer = request.scope.get("client")
    if peer is None:
        raise AuthorityDenied("Client address is unavailable")
    forwarded = [
        value
        for key, value in request.scope.get("headers", [])
        if key.lower() == b"x-forwarded-for"
    ]
    if settings.app_env in {Environment.LOCAL, Environment.TEST}:
        if forwarded:
            raise AuthorityDenied("Forwarded client address is not accepted")
        if settings.app_env == Environment.TEST and peer[0] == "testclient":
            return "127.0.0.1"
        try:
            return str(ip_address(peer[0]))
        except ValueError as exc:
            raise AuthorityDenied("Client address is unavailable") from exc
    require_trusted_ingress(request, settings)
    if len(forwarded) != 1:
        raise AuthorityDenied("Trusted ingress client address is required")
    try:
        raw = forwarded[0].decode("ascii", "strict")
        if "," in raw or raw != raw.strip():
            raise ValueError("forward chain")
        return str(ip_address(raw))
    except (UnicodeDecodeError, ValueError) as exc:
        raise AuthorityDenied("Trusted ingress client address is invalid") from exc


def canonical_authority(request: Request, settings: Settings) -> tuple[str, str]:
    """Return normalized hostname and public origin, never a forwarded host.

    Uvicorn must run with proxy-header processing disabled. In remote
    environments an authenticated origin middleware or configured ingress peer
    must establish authority before application routes are reached.
    """
    raw_headers = request.scope.get("headers", [])
    hosts = [value for key, value in raw_headers if key.lower() == b"host"]
    if len(hosts) != 1:
        raise AuthorityDenied("Invalid request authority")
    if any(key.lower() in {b"forwarded", b"x-forwarded-host"} for key, _ in raw_headers):
        raise AuthorityDenied("Forwarded authority is not accepted")
    if settings.app_env in {Environment.STAGING, Environment.PRODUCTION}:
        require_trusted_ingress(request, settings)
    try:
        authority = hosts[0].decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise AuthorityDenied("Invalid request authority") from exc
    if (
        not authority
        or authority != authority.strip()
        or any(character.isspace() for character in authority)
        or "," in authority
        or "@" in authority
        or "[" in authority
    ):
        raise AuthorityDenied("Invalid request authority")
    hostname, separator, port = authority.partition(":")
    if separator:
        if (
            settings.app_env not in {Environment.LOCAL, Environment.TEST}
            or not port.isascii()
            or not port.isdecimal()
            or not 1 <= int(port) <= 65535
        ):
            raise AuthorityDenied("Invalid request authority")
    try:
        host = (
            "testserver"
            if hostname == "testserver" and settings.app_env == Environment.TEST
            else normalize_hostname(hostname)
        )
    except TenantResolutionError as exc:
        raise AuthorityDenied("Invalid request authority") from exc
    if request.url.path.startswith("/api/v1/platform"):
        if settings.platform_host is None or host != settings.platform_host:
            raise AuthorityDenied("Platform host required")
    # The shared application host may serve tenant routes only through a
    # signed routing context, checked in the request middleware. The service
    # still requires a tenant-bound session and membership for every action.
    origin = (
        settings.local_public_origin
        if settings.app_env == Environment.LOCAL
        and settings.local_public_origin is not None
        and host == settings.platform_host
        else (
            request.url.scheme
            if settings.app_env in {Environment.LOCAL, Environment.TEST}
            else "https"
        )
        + "://"
        + authority.lower()
    )
    return host, origin

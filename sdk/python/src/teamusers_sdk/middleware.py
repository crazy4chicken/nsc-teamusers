"""Framework-neutral authentication and authorization helpers."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .permissions import AllowResult, CheckResult, PermissionsClient
from .verifier import Claims, SDKError, TokenVerificationError, Verifier
from .types import Resource


class UnauthorizedError(SDKError):
    """The request is not authenticated (HTTP 401)."""

    code = "UNAUTHORIZED"
    status_code = 401
    status = 401
    statusCode = 401


class ForbiddenError(SDKError):
    """The authenticated subject lacks a permission (HTTP 403)."""

    code = "FORBIDDEN"
    status_code = 403
    status = 403
    statusCode = 403


AuthenticationError = UnauthorizedError
AuthorizationError = ForbiddenError


def _request_headers(request: Any) -> Mapping[str, Any]:
    if isinstance(request, Mapping):
        headers = request.get("headers", request.get("Headers", request))
    else:
        headers = getattr(request, "headers", getattr(request, "Headers", {}))
    return headers if isinstance(headers, Mapping) else {}


def _authorization_header(headers: Mapping[str, Any]) -> str | None:
    for key, value in headers.items():
        if str(key).lower() == "authorization":
            if isinstance(value, bytes):
                try:
                    value = value.decode("utf-8")
                except UnicodeDecodeError:
                    return None
            return value if isinstance(value, str) else None
    return None


def _bearer_token(header: str | None) -> str | None:
    if not isinstance(header, str):
        return None
    parts = header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        return None
    return parts[1]


def Authenticate(request: Any, verifier: Verifier | None = None) -> Claims:
    """Verify a bearer token from a minimal request shape.

    The argument order mirrors the TypeScript/Go middleware helper.  For
    compatibility with early Python callers, ``Authenticate(verifier,
    request)`` is accepted as well.
    """

    if isinstance(request, Verifier) and verifier is not None and not isinstance(verifier, Verifier):
        request, verifier = verifier, request
    if verifier is None:
        raise UnauthorizedError("authentication verifier unavailable")
    token = _bearer_token(_authorization_header(_request_headers(request)))
    if token is None:
        raise UnauthorizedError("bearer token is required")
    try:
        return verifier.verify(token)
    except SDKError as error:
        raise UnauthorizedError("authentication failed", error) from error
    except Exception as error:
        raise UnauthorizedError("authentication failed", error) from error


def authenticate(request: Any, verifier: Verifier | None = None) -> Claims:
    return Authenticate(request, verifier)


def _client_allow(
    client: Any,
    claims: Claims,
    permission: str,
    resource: Resource | Mapping[str, Any] | None,
) -> tuple[bool, str]:
    method = getattr(client, "Allow", None) or getattr(client, "allow", None)
    if not callable(method):
        return False, "authorization client unavailable"
    try:
        result = method(claims, permission, resource)
    except SDKError:
        return False, "authorization service unavailable"
    if isinstance(result, tuple):
        if len(result) >= 2:
            return bool(result[0]), str(result[1])
        if len(result) == 1:
            return bool(result[0]), ""
    if hasattr(result, "allow"):
        return bool(result.allow), str(getattr(result, "reason", ""))
    return bool(result), "permission granted" if result else "permission denied"


def Require(
    client: Any,
    request: Any = None,
    claims: Claims | None = None,
    permission: str | None = None,
    resource: Resource | Mapping[str, Any] | Callable[[Any], Resource | Mapping[str, Any]] | None = None,
):
    """Require one permission, returning claims or raising a typed 403.

    The direct form is ``Require(client, request, claims, permission,
    resource)``.  Calling ``Require(client, permission)`` returns a handler
    accepting ``request`` and optional ``claims`` for middleware composition.
    """

    if isinstance(request, str) and permission is None:
        configured_permission = request
        resource_from = resource if callable(resource) else None

        def handler(next_request: Any, next_claims: Claims | None = None, next_resource: Any = None) -> Claims:
            resolved_resource = next_resource
            if resolved_resource is None and resource_from is not None:
                resolved_resource = resource_from(next_request)
            return Require(client, next_request, next_claims, configured_permission, resolved_resource)

        return handler

    if permission is None or not isinstance(permission, str):
        raise ForbiddenError("permission is required")
    if claims is None:
        verifier = getattr(client, "verifier", getattr(client, "Verifier", None))
        claims = Authenticate(request, verifier)
    allowed, reason = _client_allow(client, claims, permission, resource if not callable(resource) else resource(request))
    if not allowed:
        raise ForbiddenError(reason or "permission denied")
    return claims


def require(
    client: Any,
    request: Any = None,
    claims: Claims | None = None,
    permission: str | None = None,
    resource: Resource | Mapping[str, Any] | Callable[[Any], Resource | Mapping[str, Any]] | None = None,
):
    return Require(client, request, claims, permission, resource)


@dataclass(slots=True)
class Client:
    """Verifier plus optional local/remote permission authorization."""

    verifier: Verifier | None = None
    permissions: PermissionsClient | None = None
    remote_only: bool = False

    @property
    def Verifier(self) -> Verifier | None:
        return self.verifier

    @property
    def Permissions(self) -> PermissionsClient | None:
        return self.permissions

    @property
    def RemoteOnly(self) -> bool:
        return self.remote_only

    def authenticate(self, request: Any) -> Claims:
        return Authenticate(request, self.verifier)

    def Authenticate(self, request: Any) -> Claims:
        return self.authenticate(request)

    def allow(
        self,
        claims: Claims,
        permission: str,
        resource: Resource | Mapping[str, Any] | None = None,
    ) -> AllowResult:
        if self.permissions is None:
            return AllowResult(False, "authorization client unavailable")
        return self.permissions.allow(claims, permission, resource, remote_only=self.remote_only)

    def Allow(
        self,
        claims: Claims,
        permission: str,
        resource: Resource | Mapping[str, Any] | None = None,
    ) -> AllowResult:
        return self.allow(claims, permission, resource)

    def check(
        self,
        subject: str,
        permission: str,
        resource: Resource | Mapping[str, Any] | None = None,
    ) -> CheckResult:
        if self.permissions is None:
            return CheckResult(allow=False, reason="authorization client unavailable")
        return self.permissions.check(subject, permission, resource)

    def Check(
        self,
        subject: str,
        permission: str,
        resource: Resource | Mapping[str, Any] | None = None,
    ) -> CheckResult:
        return self.check(subject, permission, resource)

    def require(self, permission: str, resource_from: Callable[[Any], Any] | None = None):
        return Require(self, permission, resource=resource_from)

    def Require(self, permission: str, resource_from: Callable[[Any], Any] | None = None):
        return self.require(permission, resource_from)

    def middleware(self, request: Any, next_handler: Callable[[Any, Claims], Any] | None = None) -> Any:
        claims = self.authenticate(request)
        if next_handler is None:
            return claims
        return next_handler(request, claims)

    def Middleware(self, request: Any, next_handler: Callable[[Any, Claims], Any] | None = None) -> Any:
        return self.middleware(request, next_handler)

    def SubscribePermissions(self, source_or_url: Any, handler: Callable[[list[str]], Any] | None = None):
        if self.permissions is None:
            raise UnauthorizedError("permission client is unavailable")
        return self.permissions.SubscribePermissions(source_or_url, handler)


NewClient = Client


__all__ = [
    "AuthenticationError",
    "AuthorizationError",
    "Authenticate",
    "Client",
    "ForbiddenError",
    "NewClient",
    "Require",
    "UnauthorizedError",
    "authenticate",
    "require",
]

"""Permission cache and authorization helpers."""

from __future__ import annotations

import inspect
import json
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, NamedTuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request as URLRequest
from urllib.request import urlopen

from .types import (
    CompiledCondition,
    ConditionCompileError,
    Context,
    Permission,
    Request,
    Resource,
    Subject,
    compile_condition,
    match,
    parse_permission,
)
from .verifier import Claims, SDKError

DEFAULT_PERMISSION_TTL_SECONDS = 2 * 60
PermissionFetcher = Callable[..., Mapping[str, Any]]
TokenSource = Callable[[], str]

_RFC3339_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
)


class PermissionsError(SDKError):
    """Base class for permission-cache and remote authorization failures."""

    code = "PERMISSIONS_ERROR"


class PermissionConfigurationError(PermissionsError):
    """The permission client lacks a required configuration value."""

    code = "INVALID_PERMISSIONS_CONFIGURATION"


class PermissionFetchError(PermissionsError):
    """The permissions endpoint did not return a usable response."""

    code = "PERMISSIONS_FETCH_FAILED"


class PermissionSnapshotError(PermissionFetchError):
    """A v2 permission snapshot is malformed, unsupported, or expired."""


class AuthorizationCheckError(PermissionsError):
    """The remote authorization check failed."""

    code = "AUTHORIZATION_CHECK_FAILED"


@dataclass(frozen=True, slots=True)
class Grant:
    """One effective permission and its optional ABAC condition."""

    key: str
    condition: CompiledCondition | str | None = None
    team_id: str | None = None
    _permission: Permission = field(init=False, repr=False, compare=False)
    _condition_error: ConditionCompileError | None = field(init=False, repr=False, compare=False)
    _condition_source: str | None = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        permission = parse_permission(self.key)
        condition = self.condition
        condition_error = None
        condition_source = None
        if isinstance(condition, str):
            condition_source = condition
            try:
                condition = compile_condition(condition)
            except ConditionCompileError as error:
                condition_error = error
                condition = None
        elif condition is not None and not isinstance(condition, CompiledCondition):
            raise TypeError("grant condition must be a CompiledCondition or string")
        elif isinstance(condition, CompiledCondition):
            condition_source = condition.source
        if self.team_id is not None and (not isinstance(self.team_id, str) or not self.team_id):
            raise TypeError("grant team_id must be a nonempty string or None")
        object.__setattr__(self, "_permission", permission)
        object.__setattr__(self, "condition", condition)
        object.__setattr__(self, "_condition_error", condition_error)
        object.__setattr__(self, "_condition_source", condition_source)

    @property
    def Key(self) -> str:
        return self.key

    @property
    def Condition(self) -> CompiledCondition | None:
        return self.condition

    @property
    def permission(self) -> Permission:
        return self._permission

    @property
    def Permission(self) -> Permission:
        return self._permission

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"key": self.key}
        condition_source = self.condition.source if self.condition is not None else self._condition_source
        if condition_source is not None and condition_source.strip():
            value["condition"] = condition_source
        if self.team_id is not None:
            value["team_id"] = self.team_id
        return value

    def MarshalJSON(self) -> dict[str, Any]:
        return self.to_dict()


@dataclass(frozen=True, slots=True)
class PermissionEntry:
    """Cached effective permissions for one user."""

    user_id: str
    perm_ver: int
    grants: tuple[Grant, ...] = ()
    valid_until: str | None = None

    @property
    def UserID(self) -> str:
        return self.user_id

    @property
    def PermVer(self) -> int:
        return self.perm_ver

    @property
    def Grants(self) -> tuple[Grant, ...]:
        return self.grants

    def to_dict(self) -> dict[str, Any]:
        value = {
            "user_id": self.user_id,
            "perm_ver": self.perm_ver,
            "grants": [grant.to_dict() for grant in self.grants],
        }
        if self.valid_until is not None:
            value["valid_until"] = self.valid_until
        return value


Permissions = PermissionEntry
CachedPermissions = PermissionEntry


@dataclass(frozen=True, slots=True)
class CheckResult:
    """Response from the authoritative remote authorization endpoint."""

    allow: bool
    matched: tuple[str, ...] = ()
    reason: str = ""

    @property
    def Allow(self) -> bool:
        return self.allow

    @property
    def Matched(self) -> tuple[str, ...]:
        return self.matched

    @property
    def Reason(self) -> str:
        return self.reason

    def __iter__(self):
        # Allows the common ``allowed, reason = client.Check(...)`` spelling
        # while retaining the richer Go-shaped CheckResult object.
        yield self.allow
        yield self.reason


class AllowResult(NamedTuple):
    """Local authorization decision with tuple unpacking compatibility."""

    allow: bool
    reason: str

    @property
    def Allow(self) -> bool:
        return self.allow

    @property
    def Reason(self) -> str:
        return self.reason


@dataclass(slots=True)
class _Inflight:
    done: threading.Event = field(default_factory=threading.Event)
    entry: PermissionEntry | None = None
    error: BaseException | None = None
    clear_epoch: int = 0
    user_epoch: int = 0


@dataclass(slots=True)
class _CachedEntry:
    entry: PermissionEntry
    expires_at: float


class PermissionsClient:
    """Cache effective permissions and call the authorization service."""

    def __init__(
        self,
        base_url: str,
        service_token: str | None = None,
        *,
        token: str | None = None,
        token_source: TokenSource | None = None,
        service_token_source: TokenSource | None = None,
        ttl: float = DEFAULT_PERMISSION_TTL_SECONDS,
        ttl_seconds: float | None = None,
        fetcher: PermissionFetcher | None = None,
        fetch: PermissionFetcher | None = None,
        requester: Callable[..., Any] | None = None,
    ) -> None:
        self.base_url = base_url.strip().rstrip("/")
        configured_token = service_token if service_token is not None else token
        self.service_token = configured_token.strip() if isinstance(configured_token, str) else ""
        self.token_source = token_source or service_token_source
        configured_ttl = ttl_seconds if ttl_seconds is not None else ttl
        if not isinstance(configured_ttl, (int, float)) or isinstance(configured_ttl, bool):
            raise PermissionConfigurationError("permission cache TTL must be a finite non-negative number")
        if configured_ttl < 0 or configured_ttl != configured_ttl or configured_ttl in (float("inf"), float("-inf")):
            raise PermissionConfigurationError("permission cache TTL must be a finite non-negative number")
        self.ttl = float(configured_ttl)
        self._fetcher = fetcher or fetch
        self._requester = requester
        self._lock = threading.RLock()
        self._entries: dict[str, _CachedEntry] = {}
        self._inflight: dict[str, _Inflight] = {}
        self._clear_epoch = 0
        self._user_epochs: dict[str, int] = {}

    @property
    def base(self) -> str:
        return self.base_url

    def _service_bearer(self) -> str:
        source = self.token_source
        if source is not None:
            try:
                value = source()
            except Exception as error:
                raise PermissionConfigurationError("get service token", error) from error
        else:
            value = self.service_token
        if not isinstance(value, str) or not value.strip():
            raise PermissionConfigurationError("service token is not configured")
        return value.strip()

    def get(
        self,
        user_id: str,
        token_perm_ver: int | Claims | None = None,
        *,
        perm_ver: int | None = None,
    ) -> PermissionEntry:
        """Return one user's effective grants using a per-user single-flight."""

        user_id = user_id.strip() if isinstance(user_id, str) else ""
        if not user_id:
            raise PermissionFetchError("user ID is empty")
        if token_perm_ver is None:
            token_perm_ver = perm_ver
        if hasattr(token_perm_ver, "perm_ver"):
            token_perm_ver = int(getattr(token_perm_ver, "perm_ver"))
        if isinstance(token_perm_ver, bool) or not isinstance(token_perm_ver, int):
            raise PermissionFetchError("token permission version is invalid")

        with self._lock:
            cached = self._entries.get(user_id)
            if (
                cached is not None
                and cached.expires_at > time.monotonic()
                and cached.entry.perm_ver == token_perm_ver
                and not _snapshot_expired(cached.entry)
            ):
                return _clone_entry(cached.entry)
            call = self._inflight.get(user_id)
            owner = call is None
            if owner:
                call = _Inflight(
                    clear_epoch=self._clear_epoch,
                    user_epoch=self._user_epochs.get(user_id, 0),
                )
                self._inflight[user_id] = call
        assert call is not None

        if not owner:
            call.done.wait()
            with self._lock:
                if self._inflight_invalidated(user_id, call):
                    raise PermissionSnapshotError("permission cache invalidated during fetch")
                if call.error is not None:
                    raise call.error
                if call.entry is None:
                    raise PermissionFetchError("permission fetch returned no entry")
                entry = call.entry
            if _snapshot_expired(entry):
                raise PermissionSnapshotError("permission snapshot valid_until is expired")
            return _clone_entry(entry)

        try:
            entry = self._fetch_permissions(user_id)
            monotonic_now = time.monotonic()
            expires_at = monotonic_now + self.ttl
            if entry.valid_until is not None:
                deadline = _parse_rfc3339(entry.valid_until)
                wall_now = datetime.now(timezone.utc)
                if deadline is None or deadline <= wall_now:
                    raise PermissionSnapshotError("permission snapshot valid_until is expired or invalid")
                expires_at = min(expires_at, monotonic_now + (deadline - wall_now).total_seconds())
        except BaseException as error:
            with self._lock:
                if self._inflight_invalidated(user_id, call):
                    error = PermissionSnapshotError("permission cache invalidated during fetch")
                if self._inflight.get(user_id) is call:
                    self._inflight.pop(user_id)
                call.error = error
                call.done.set()
            raise error
        invalidation_error = None
        with self._lock:
            if self._inflight_invalidated(user_id, call):
                invalidation_error = PermissionSnapshotError("permission cache invalidated during fetch")
                if self._inflight.get(user_id) is call:
                    self._inflight.pop(user_id)
                call.error = invalidation_error
            else:
                if self._inflight.get(user_id) is call:
                    self._inflight.pop(user_id)
                call.entry = entry
                self._entries[user_id] = _CachedEntry(
                    entry=_clone_entry(entry), expires_at=expires_at
                )
            call.done.set()
        if invalidation_error is not None:
            raise invalidation_error
        if _snapshot_expired(entry):
            self.invalidate(user_id)
            raise PermissionSnapshotError("permission snapshot valid_until is expired")
        return _clone_entry(entry)

    def _inflight_invalidated(self, user_id: str, call: _Inflight) -> bool:
        return (
            self._clear_epoch != call.clear_epoch
            or self._user_epochs.get(user_id, 0) != call.user_epoch
        )

    def Get(
        self,
        user_id: str,
        token_perm_ver: int | Claims | None = None,
        *,
        perm_ver: int | None = None,
    ) -> PermissionEntry:
        return self.get(user_id, token_perm_ver, perm_ver=perm_ver)

    def invalidate(self, *user_ids: str | list[str] | tuple[str, ...] | set[str]) -> None:
        if len(user_ids) == 1 and isinstance(user_ids[0], (list, tuple, set)):
            user_ids = tuple(user_ids[0])
        with self._lock:
            for user_id in user_ids:
                if isinstance(user_id, str) and user_id.strip():
                    normalized = user_id.strip()
                    self._user_epochs[normalized] = self._user_epochs.get(normalized, 0) + 1
                    self._entries.pop(normalized, None)
                    self._inflight.pop(normalized, None)

    def Invalidate(self, *user_ids: str) -> None:
        self.invalidate(*user_ids)

    def invalidate_permissions(self, *user_ids: str) -> None:
        self.invalidate(*user_ids)

    def InvalidatePermissions(self, *user_ids: str) -> None:
        self.invalidate(*user_ids)

    def invalidate_all(self) -> None:
        with self._lock:
            self._clear_epoch += 1
            self._user_epochs.clear()
            self._inflight.clear()
            self._entries.clear()

    def InvalidateAll(self) -> None:
        self.invalidate_all()

    def clear(self) -> None:
        self.invalidate_all()

    def Clear(self) -> None:
        self.clear()

    def _fetch_permissions(self, user_id: str) -> PermissionEntry:
        if not self.base_url:
            raise PermissionConfigurationError("authorization base URL is empty")
        token = self._service_bearer()
        endpoint = f"{self.base_url}/authz/permissions/{quote(user_id, safe='')}?version=2"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        try:
            payload = self._request_json("GET", endpoint, headers, None, snapshot=True)
        except PermissionsError:
            raise
        except Exception as error:
            raise PermissionFetchError("fetch permissions", error) from error
        if not isinstance(payload, Mapping):
            raise PermissionSnapshotError("decode permissions: object expected")
        if type(payload.get("version")) is not int or payload["version"] != 2:
            raise PermissionSnapshotError("decode permissions: version must be 2")
        payload_user = payload.get("user_id")
        if not isinstance(payload_user, str) or not payload_user:
            raise PermissionSnapshotError("decode permissions: user_id must be a nonempty string")
        if payload_user != user_id:
            raise PermissionSnapshotError(
                f"permissions response user_id {payload_user!r} does not match {user_id!r}"
            )
        raw_ver = payload.get("perm_ver")
        if type(raw_ver) is not int or raw_ver < 0:
            raise PermissionSnapshotError("decode permissions: perm_ver must be a non-negative integer")
        raw_grants = payload.get("grants")
        if not isinstance(raw_grants, list):
            raise PermissionSnapshotError("decode permissions: grants must be an array")
        valid_until: str | None = None
        if "valid_until" in payload:
            raw_deadline = payload["valid_until"]
            if not isinstance(raw_deadline, str):
                raise PermissionSnapshotError("decode permissions: valid_until must be an RFC3339 string")
            deadline = _parse_rfc3339(raw_deadline)
            if deadline is None:
                raise PermissionSnapshotError("decode permissions: valid_until must be an RFC3339 string")
            if deadline <= datetime.now(timezone.utc):
                raise PermissionSnapshotError("decode permissions: valid_until is expired")
            valid_until = raw_deadline
        grants = tuple(_parse_snapshot_grant(value) for value in raw_grants)
        return PermissionEntry(
            user_id=user_id,
            perm_ver=raw_ver,
            grants=grants,
            valid_until=valid_until,
        )

    def _request_json(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        *,
        snapshot: bool = False,
    ) -> Any:
        if self._requester is not None:
            return _call_requester(self._requester, method, url, headers, body)
        if self._fetcher is not None and method == "GET":
            return _call_fetcher(self._fetcher, url, headers)
        request = URLRequest(url, data=body, headers=dict(headers), method=method)
        try:
            with urlopen(request, timeout=10) as response:
                status = getattr(response, "status", 200)
                if not 200 <= status < 300:
                    if snapshot and status == 400:
                        raise PermissionSnapshotError(f"HTTP {status}")
                    raise PermissionFetchError(f"HTTP {status}")
                return json.load(response)
        except HTTPError as error:
            if snapshot and error.code == 400:
                raise PermissionSnapshotError(f"HTTP {error.code}", error) from error
            raise PermissionFetchError("HTTP request failed", error) from error
        except PermissionFetchError:
            raise
        except ValueError as error:
            if snapshot:
                raise PermissionSnapshotError("decode permission snapshot", error) from error
            raise PermissionFetchError("HTTP request failed", error) from error
        except (OSError, URLError) as error:
            raise PermissionFetchError("HTTP request failed", error) from error

    def check(self, subject: str, permission: str, resource: Resource | Mapping[str, Any] | None = None) -> CheckResult:
        """Perform an authoritative remote authorization check."""

        if not isinstance(subject, str) or not subject.strip():
            raise AuthorizationCheckError("subject is empty")
        parse_permission(permission)
        resource_value = _coerce_resource(resource)
        body = json.dumps(
            {
                "subject": subject,
                "permission": permission,
                "context": {"resource": _resource_dict(resource_value)},
            },
            separators=(",", ":"),
        ).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self._service_bearer()}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        endpoint = f"{self.base_url}/authz/check"
        try:
            payload = self._request_json("POST", endpoint, headers, body)
        except PermissionsError as error:
            raise AuthorizationCheckError(str(error), error) from error
        except Exception as error:
            raise AuthorizationCheckError("remote authorization check", error) from error
        if not isinstance(payload, Mapping):
            raise AuthorizationCheckError("decode authorization response: object expected")
        allowed = payload.get("allow")
        if not isinstance(allowed, bool):
            raise AuthorizationCheckError("decode authorization response: allow must be boolean")
        matched_raw = payload.get("matched", [])
        matched = tuple(value for value in matched_raw if isinstance(value, str)) if isinstance(matched_raw, list) else ()
        reason = payload.get("reason", "")
        if not isinstance(reason, str):
            reason = ""
        if not reason:
            reason = "permission granted" if allowed else "permission denied"
        return CheckResult(allow=allowed, matched=matched, reason=reason)

    def Check(self, subject: str, permission: str, resource: Resource | Mapping[str, Any] | None = None) -> CheckResult:
        return self.check(subject, permission, resource)

    def allow(
        self,
        claims: Claims,
        permission: str,
        resource: Resource | Mapping[str, Any] | None = None,
        *,
        remote_only: bool = False,
    ) -> tuple[bool, str]:
        """Evaluate a claim against local grants, falling back to /authz/check."""

        if not isinstance(claims, Claims):
            raise TypeError("claims must be Claims")
        if not claims.subject:
            return AllowResult(False, "subject is missing")
        if claims.expiry and claims.expiry <= datetime.now(timezone.utc):
            return AllowResult(False, "access token is expired")
        try:
            requested = parse_permission(permission)
        except (TypeError, ValueError):
            return AllowResult(False, "invalid permission")
        resource_value = _coerce_resource(resource)
        if remote_only:
            return self._remote_allow(claims.subject, permission, resource_value)
        try:
            entry = self.get(claims.subject, claims.perm_ver)
        except PermissionSnapshotError:
            return AllowResult(False, "invalid permission snapshot")
        except PermissionsError:
            return self._remote_allow(claims.subject, permission, resource_value)
        if entry.perm_ver != claims.perm_ver:
            return AllowResult(False, "permission version mismatch")
        if entry.valid_until is not None and _snapshot_expired(entry):
            return AllowResult(False, "permission snapshot expired")
        if requested.scope == "team" and not resource_value.team_id:
            return AllowResult(False, "no matching grant")
        condition_rejected = False
        allowed = False
        denied = False
        for grant in entry.grants:
            if grant.team_id is not None and grant.team_id != resource_value.team_id:
                continue
            grant_permission = grant.permission
            candidate = grant_permission
            if grant_permission.deny:
                candidate = Permission(
                    grant_permission.resource,
                    grant_permission.action,
                    grant_permission.scope,
                    False,
                )
            if not match(candidate, requested):
                continue
            if grant._condition_error is not None:
                return AllowResult(False, "condition_error")
            if grant.condition is not None:
                context = Context(
                    subject=Subject(id=claims.subject, kind=claims.kind),
                    resource=resource_value,
                    request=Request(time=datetime.now(timezone.utc)),
                )
                try:
                    condition_matches = grant.condition.eval_strict(context)
                except Exception:
                    return AllowResult(False, "condition_error")
                if not condition_matches:
                    condition_rejected = True
                    continue
            if grant_permission.deny:
                denied = True
            else:
                allowed = True
        if denied:
            return AllowResult(False, "permission denied")
        if allowed:
            return AllowResult(True, "permission granted")
        if condition_rejected:
            return AllowResult(False, "condition denied")
        return AllowResult(False, "no matching grant")
    def _remote_allow(self, subject: str, permission: str, resource: Resource) -> tuple[bool, str]:
        try:
            result = self.check(subject, permission, resource)
        except PermissionsError as error:
            return AllowResult(False, "authorization service unavailable")
        return AllowResult(result.allow, result.reason)

    def Allow(
        self,
        claims: Claims,
        permission: str,
        resource: Resource | Mapping[str, Any] | None = None,
        *,
        remote_only: bool = False,
    ) -> AllowResult:
        return self.allow(claims, permission, resource, remote_only=remote_only)

    def SubscribePermissions(
        self,
        source_or_url: Any = None,
        handler: Callable[[list[str]], Any] | None = None,
        *,
        source: Any = None,
    ):
        from .events import subscribe_permissions

        if source is not None:
            source_or_url = source
        return subscribe_permissions(self, source_or_url, handler)

    def subscribe_permissions(
        self,
        source_or_url: Any = None,
        handler: Callable[[list[str]], Any] | None = None,
        *,
        source: Any = None,
    ):
        return self.SubscribePermissions(source_or_url, handler, source=source)


def NewPermissionsClient(base_url: str, *args: Any, **kwargs: Any) -> PermissionsClient:
    return PermissionsClient(base_url, *args, **kwargs)


def _clone_entry(entry: PermissionEntry) -> PermissionEntry:
    return PermissionEntry(
        entry.user_id,
        entry.perm_ver,
        tuple(entry.grants),
        entry.valid_until,
    )


def _parse_rfc3339(value: str) -> datetime | None:
    if not isinstance(value, str) or _RFC3339_PATTERN.fullmatch(value) is None:
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _snapshot_expired(entry: PermissionEntry) -> bool:
    if entry.valid_until is None:
        return False
    deadline = _parse_rfc3339(entry.valid_until)
    return deadline is None or deadline <= datetime.now(timezone.utc)


def _parse_snapshot_grant(value: Any) -> Grant:
    if not isinstance(value, Mapping):
        raise PermissionSnapshotError("decode permissions: grant object expected")
    key = value.get("key")
    if not isinstance(key, str) or not key.strip():
        raise PermissionSnapshotError("decode permissions: grant key must be a nonempty string")
    condition: str | None = None
    if "condition" in value:
        raw_condition = value["condition"]
        if not isinstance(raw_condition, str) or not raw_condition.strip():
            raise PermissionSnapshotError("decode permissions: grant condition must be a nonempty string")
        condition = raw_condition
    team_id: str | None = None
    if "team_id" in value:
        raw_team_id = value["team_id"]
        if raw_team_id is not None:
            if not isinstance(raw_team_id, str) or not raw_team_id:
                raise PermissionSnapshotError("decode permissions: grant team_id must be nonempty or null")
            team_id = raw_team_id
    try:
        return Grant(key, condition, team_id)
    except (TypeError, ValueError) as error:
        raise PermissionSnapshotError("decode permissions: invalid grant", error) from error


def _coerce_resource(resource: Resource | Mapping[str, Any] | None) -> Resource:
    if resource is None:
        return Resource()
    if isinstance(resource, Resource):
        return resource
    if isinstance(resource, Mapping):
        attrs = resource.get("attrs", resource.get("Attrs"))
        return Resource(
            owner_id=str(resource.get("owner_id", resource.get("ownerID", "")) or ""),
            team_id=str(resource.get("team_id", resource.get("teamID", "")) or ""),
            attrs=attrs if isinstance(attrs, Mapping) else None,
        )
    raise TypeError("resource must be Resource, mapping, or None")


def _resource_dict(resource: Resource) -> dict[str, Any]:
    return {
        "owner_id": resource.owner_id,
        "team_id": resource.team_id,
        "attrs": dict(resource.attrs) if isinstance(resource.attrs, Mapping) else {},
    }


def _call_fetcher(fetcher: Callable[..., Any], url: str, headers: Mapping[str, str]) -> Any:
    try:
        signature = inspect.signature(fetcher)
        positional = [
            parameter
            for parameter in signature.parameters.values()
            if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
        ]
        accepts_varargs = any(
            parameter.kind == parameter.VAR_POSITIONAL for parameter in signature.parameters.values()
        )
        if accepts_varargs or len(positional) >= 2:
            return fetcher(url, dict(headers))
        if any(parameter.kind == parameter.KEYWORD_ONLY and parameter.name == "headers" for parameter in signature.parameters.values()):
            return fetcher(url, headers=dict(headers))
    except (TypeError, ValueError):
        pass
    return fetcher(url)


def _call_requester(requester: Callable[..., Any], method: str, url: str, headers: Mapping[str, str], body: bytes | None) -> Any:
    try:
        signature = inspect.signature(requester)
        positional = [
            parameter
            for parameter in signature.parameters.values()
            if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
        ]
        accepts_varargs = any(
            parameter.kind == parameter.VAR_POSITIONAL for parameter in signature.parameters.values()
        )
        if accepts_varargs or len(positional) >= 4:
            return requester(method, url, dict(headers), body)
        if len(positional) == 3:
            return requester(method, url, body)
        if len(positional) == 2:
            return requester(url, dict(headers))
    except (TypeError, ValueError):
        pass
    return requester(url)


class ConditionError(ValueError):
    """Compatibility marker for invalid grant conditions."""

__all__ = [
    "AuthorizationCheckError",
    "AllowResult",
    "CachedPermissions",
    "NewPermissionsClient",
    "DEFAULT_PERMISSION_TTL_SECONDS",
    "Grant",
    "PermissionConfigurationError",
    "PermissionEntry",
    "PermissionFetchError",
    "PermissionSnapshotError",
    "Permissions",
    "PermissionsClient",
    "PermissionsError",
]

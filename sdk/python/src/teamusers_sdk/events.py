"""Optional NATS event subscriptions."""

from __future__ import annotations

import asyncio
import inspect
import json
import threading
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Literal, TypeVar, TypedDict, cast

from .verifier import SDKError

PERMISSION_EVENT_SUBJECTS = (
    "iam.perm.changed",
    "iam.user.disabled",
    "iam.role.updated",
)

KEY_ROTATION_EVENT_SUBJECT = "iam.key.rotated"

USER_CREATED_EVENT_SUBJECT = "iam.user.created"
USER_UPDATED_EVENT_SUBJECT = "iam.user.updated"
USER_DELETED_EVENT_SUBJECT = "iam.user.deleted"
TEAM_CREATED_EVENT_SUBJECT = "iam.team.created"
TEAM_UPDATED_EVENT_SUBJECT = "iam.team.updated"

USER_CREATED_EVENT_KIND = "user.created"
USER_UPDATED_EVENT_KIND = "user.updated"
USER_DELETED_EVENT_KIND = "user.deleted"
TEAM_CREATED_EVENT_KIND = "team.created"
TEAM_UPDATED_EVENT_KIND = "team.updated"


class UserCreatedEvent(TypedDict):
    event_id: int
    type: Literal["user.created"]
    user_id: str
    changed_fields: list[str]
    at: str


class UserUpdatedEvent(TypedDict):
    event_id: int
    type: Literal["user.updated"]
    user_id: str
    changed_fields: list[str]
    at: str


class UserDeletedEvent(TypedDict):
    event_id: int
    type: Literal["user.deleted"]
    user_id: str
    at: str

class TeamCreatedEvent(TypedDict):
    event_id: int
    type: Literal["team.created"]
    team_id: str
    changed_fields: list[str]
    at: str


class TeamUpdatedEvent(TypedDict):
    event_id: int
    type: Literal["team.updated"]
    team_id: str
    changed_fields: list[str]
    at: str


_LifecycleEventT = TypeVar("_LifecycleEventT")


class NATSSubscriptionError(SDKError):
    """NATS could not be loaded or a subscription could not be created."""

    code = "NATS_SUBSCRIPTION_FAILED"


class NATSUnavailableError(NATSSubscriptionError):
    """The optional nats-py package is not installed."""

    code = "NATS_DEPENDENCY_MISSING"


class PermissionSubscription:
    """A closeable SDK event subscription."""

    def __init__(self, closers: Sequence[Callable[[], Any]] = ()) -> None:
        self._closers = list(closers)
        self._lock = threading.Lock()
        self._closed = False

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            closers = list(self._closers)
            self._closers.clear()
        first_error: BaseException | None = None
        for closer in closers:
            try:
                result = closer()
                if inspect.isawaitable(result):
                    _run_awaitable(result)
            except BaseException as error:
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error

    def Close(self) -> None:
        self.close()


# A short alias is convenient in type annotations and mirrors the Go name.
Subscription = PermissionSubscription


def subscribe_permissions(
    client: Any,
    source_or_url: Any,
    handler: Callable[[list[str]], Any] | None = None,
) -> PermissionSubscription | None:
    """Subscribe to the three invalidation subjects.

    ``source_or_url`` may be a NATS URL or an injected synchronous source.  The
    source seam keeps tests and applications that already own a NATS connection
    independent of the optional nats-py package.
    """

    if client is None:
        raise NATSSubscriptionError("permission client is unavailable")
    if isinstance(source_or_url, str):
        if not source_or_url.strip():
            return None
        try:
            import nats  # type: ignore[import-not-found]
        except ImportError as error:
            raise NATSUnavailableError(
                "NATS support requires the optional 'nats-py' extra; install teamusers-sdk[nats]"
            ) from error
        source = _NATSSource(nats, source_or_url.strip())
    else:
        if source_or_url is None:
            raise NATSSubscriptionError("NATS subscription source is required")
        source = source_or_url

    callback = _event_callback(client, handler)
    try:
        return _subscribe_source(source, callback)
    except NATSSubscriptionError:
        raise
    except Exception as error:
        raise NATSSubscriptionError("subscribe to permission events", error) from error


def SubscribePermissions(
    client: Any,
    source_or_url: Any,
    handler: Callable[[list[str]], Any] | None = None,
) -> PermissionSubscription | None:
    return subscribe_permissions(client, source_or_url, handler)

def subscribe_key_rotations(verifier: Any, source_or_url: Any) -> PermissionSubscription | None:
    """Refresh a verifier's JWKS cache on the key-rotation subject."""

    if verifier is None:
        raise NATSSubscriptionError("verifier is unavailable")
    if isinstance(source_or_url, str):
        if not source_or_url.strip():
            return None
        try:
            import nats  # type: ignore[import-not-found]
        except ImportError as error:
            raise NATSUnavailableError(
                "NATS support requires the optional 'nats-py' extra; install teamusers-sdk[nats]"
            ) from error
        source = _NATSSource(nats, source_or_url.strip())
    else:
        if source_or_url is None:
            raise NATSSubscriptionError("NATS subscription source is required")
        source = source_or_url

    def ignore_refresh_error(future: asyncio.Future[Any]) -> None:
        try:
            future.result()
        except Exception:
            # Verification retries a missed key through the normal refresh path.
            pass

    def on_message(*_message: Any) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            try:
                verifier.refresh_jwks()
            except Exception:
                # Verification retries a missed key through the normal refresh path.
                pass
            return
        try:
            future = loop.run_in_executor(None, verifier.refresh_jwks)
        except Exception:
            # Verification retries a missed key through the normal refresh path.
            pass
        else:
            future.add_done_callback(ignore_refresh_error)

    try:
        return _subscribe_source(source, on_message, (KEY_ROTATION_EVENT_SUBJECT,))
    except NATSSubscriptionError:
        raise
    except Exception as error:
        raise NATSSubscriptionError("subscribe to key rotation events", error) from error


def SubscribeKeyRotations(verifier: Any, source_or_url: Any) -> PermissionSubscription | None:
    return subscribe_key_rotations(verifier, source_or_url)


def subscribe_user_created(
    source_or_url: Any,
    handler: Callable[[UserCreatedEvent], Any],
) -> PermissionSubscription | None:
    """Subscribe a callback to user.created lifecycle events."""
    return _subscribe_lifecycle_event(
        source_or_url,
        USER_CREATED_EVENT_SUBJECT,
        USER_CREATED_EVENT_KIND,
        "user_id",
        handler,
    )


def subscribe_user_updated(
    source_or_url: Any,
    handler: Callable[[UserUpdatedEvent], Any],
) -> PermissionSubscription | None:
    """Subscribe a callback to user.updated lifecycle events."""
    return _subscribe_lifecycle_event(
        source_or_url,
        USER_UPDATED_EVENT_SUBJECT,
        USER_UPDATED_EVENT_KIND,
        "user_id",
        handler,
    )

def subscribe_user_deleted(
    source_or_url: Any,
    handler: Callable[[UserDeletedEvent], Any],
) -> PermissionSubscription | None:
    """Subscribe a callback to user.deleted lifecycle events."""
    return _subscribe_lifecycle_event(
        source_or_url,
        USER_DELETED_EVENT_SUBJECT,
        USER_DELETED_EVENT_KIND,
        "user_id",
        handler,
        changed_fields_required=False,
    )

def subscribe_team_created(
    source_or_url: Any,
    handler: Callable[[TeamCreatedEvent], Any],
) -> PermissionSubscription | None:
    """Subscribe a callback to team.created lifecycle events."""
    return _subscribe_lifecycle_event(
        source_or_url,
        TEAM_CREATED_EVENT_SUBJECT,
        TEAM_CREATED_EVENT_KIND,
        "team_id",
        handler,
    )


def subscribe_team_updated(
    source_or_url: Any,
    handler: Callable[[TeamUpdatedEvent], Any],
) -> PermissionSubscription | None:
    """Subscribe a callback to team.updated lifecycle events."""
    return _subscribe_lifecycle_event(
        source_or_url,
        TEAM_UPDATED_EVENT_SUBJECT,
        TEAM_UPDATED_EVENT_KIND,
        "team_id",
        handler,
    )


def SubscribeUserCreated(
    source_or_url: Any,
    handler: Callable[[UserCreatedEvent], Any],
) -> PermissionSubscription | None:
    return subscribe_user_created(source_or_url, handler)


def SubscribeUserUpdated(
    source_or_url: Any,
    handler: Callable[[UserUpdatedEvent], Any],
) -> PermissionSubscription | None:
    return subscribe_user_updated(source_or_url, handler)


def SubscribeUserDeleted(
    source_or_url: Any,
    handler: Callable[[UserDeletedEvent], Any],
) -> PermissionSubscription | None:
    return subscribe_user_deleted(source_or_url, handler)

def SubscribeTeamCreated(
    source_or_url: Any,
    handler: Callable[[TeamCreatedEvent], Any],
) -> PermissionSubscription | None:
    return subscribe_team_created(source_or_url, handler)


def SubscribeTeamUpdated(
    source_or_url: Any,
    handler: Callable[[TeamUpdatedEvent], Any],
) -> PermissionSubscription | None:
    return subscribe_team_updated(source_or_url, handler)


def _subscribe_lifecycle_event(
    source_or_url: Any,
    subject: str,
    event_kind: str,
    entity_id_field: str,
    handler: Callable[[_LifecycleEventT], Any],
    changed_fields_required: bool = True,
) -> PermissionSubscription | None:
    if isinstance(source_or_url, str):
        if not source_or_url.strip():
            return None
        try:
            import nats  # type: ignore[import-not-found]
        except ImportError as error:
            raise NATSUnavailableError(
                "NATS support requires the optional 'nats-py' extra; install teamusers-sdk[nats]"
            ) from error
        source = _NATSSource(nats, source_or_url.strip())
    else:
        if source_or_url is None:
            raise NATSSubscriptionError("NATS subscription source is required")
        source = source_or_url

    def on_message(*message: Any) -> None:
        payload = message[-1] if message else None
        event = _decode_lifecycle_event(payload, event_kind, entity_id_field, changed_fields_required)
        if event is not None:
            handler(cast(_LifecycleEventT, event))

    try:
        return _subscribe_source(source, on_message, (subject,))
    except NATSSubscriptionError:
        raise
    except Exception as error:
        raise NATSSubscriptionError(f"subscribe to {event_kind} events", error) from error


def _decode_lifecycle_event(
    payload: Any,
    event_kind: str,
    entity_id_field: str,
    changed_fields_required: bool,
) -> Mapping[str, Any] | None:
    event = _decode_event(payload)
    if event is None or event.get("type") != event_kind:
        return None
    event_id = event.get("event_id")
    if not isinstance(event_id, int) or isinstance(event_id, bool):
        return None
    entity_id = event.get(entity_id_field)
    if not isinstance(entity_id, str) or not entity_id:
        return None
    if not isinstance(event.get("at"), str):
        return None
    changed_fields = event.get("changed_fields")
    if changed_fields_required or "changed_fields" in event:
        if not isinstance(changed_fields, list):
            return None
        if not all(isinstance(field, str) for field in changed_fields):
            return None
    return event


def _event_callback(client: Any, handler: Callable[[list[str]], Any] | None):
    def on_message(*message: Any) -> None:
        payload = message[-1] if message else None
        event = _decode_event(payload)
        if event is None:
            return
        values = event.get("user_ids")
        if values is None:
            values = event.get("userIDs")
        if values is None and isinstance(event.get("user_id"), str):
            values = [event["user_id"]]
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
            return
        user_ids = [value for value in values if isinstance(value, str) and value.strip()]
        if not user_ids:
            return
        client.Invalidate(*user_ids)
        if handler is not None:
            handler(list(user_ids))

    return on_message


def _decode_event(payload: Any) -> Mapping[str, Any] | None:
    if hasattr(payload, "data"):
        payload = payload.data
    if isinstance(payload, Mapping):
        return payload
    if isinstance(payload, bytes):
        try:
            payload = payload.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if isinstance(payload, str):
        try:
            value = json.loads(payload)
        except (TypeError, ValueError):
            return None
        return value if isinstance(value, Mapping) else None
    return None


def _subscribe_source(
    source: Any,
    callback: Callable[..., Any],
    subjects: Sequence[str] = PERMISSION_EVENT_SUBJECTS,
) -> PermissionSubscription:
    closers: list[Callable[[], Any]] = []
    if isinstance(source, _NATSSource):
        return source.subscribe(callback, subjects)

    subscribe = getattr(source, "subscribe", None)
    if callable(subscribe):
        for subject in subjects:
            result = _invoke_subscribe(subscribe, subject, callback)
            closer = _closer_for(result)
            if closer is not None:
                closers.append(closer)
        source_closer = _closer_for(source)
        if source_closer is not None:
            closers.append(source_closer)
        return PermissionSubscription(closers)

    if callable(source):
        try:
            result = _invoke_factory(source, callback, subjects)
        except Exception as error:
            raise NATSSubscriptionError("create NATS subscription", error) from error
        if isinstance(result, PermissionSubscription):
            return result
        closer = _closer_for(result)
        if closer is not None:
            closers.append(closer)
        return PermissionSubscription(closers)

    raise NATSSubscriptionError("subscription source must provide subscribe() or be callable")


def _invoke_subscribe(subscribe: Callable[..., Any], subject: str, callback: Callable[..., Any]) -> Any:
    try:
        signature = inspect.signature(subscribe)
        positional = [
            parameter
            for parameter in signature.parameters.values()
            if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
        ]
        if any(parameter.kind == parameter.VAR_POSITIONAL for parameter in signature.parameters.values()) or len(positional) >= 2:
            return subscribe(subject, callback)
        return subscribe(subject=subject, callback=callback)
    except (TypeError, ValueError):
        return subscribe(subject, callback)


def _invoke_factory(
    factory: Callable[..., Any],
    callback: Callable[..., Any],
    subjects: Sequence[str],
) -> Any:
    try:
        signature = inspect.signature(factory)
        positional = [
            parameter
            for parameter in signature.parameters.values()
            if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
        ]
        if any(parameter.kind == parameter.VAR_POSITIONAL for parameter in signature.parameters.values()) or len(positional) >= 2:
            return factory(subjects, callback)
        return factory(callback)
    except (TypeError, ValueError):
        return factory(subjects, callback)


def _closer_for(value: Any) -> Callable[[], Any] | None:
    if value is None:
        return None
    if callable(value):
        return value
    for name in ("unsubscribe", "close", "stop", "Close"):
        method = getattr(value, name, None)
        if callable(method):
            return method
    return None


def _run_awaitable(value: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(value)
    result: list[Any] = []
    error: list[BaseException] = []

    def runner() -> None:
        try:
            result.append(asyncio.run(value))
        except BaseException as exc:
            error.append(exc)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join()
    if error:
        raise error[0]
    return result[0] if result else None


class _NATSSource:
    """Small sync bridge around nats-py's asyncio client."""

    def __init__(self, nats_module: Any, url: str) -> None:
        self._nats = nats_module
        self._url = url

    def subscribe(
        self,
        callback: Callable[..., Any],
        subjects: Sequence[str] = PERMISSION_EVENT_SUBJECTS,
    ) -> PermissionSubscription:
        ready = threading.Event()
        state: dict[str, Any] = {}
        stopped = threading.Event()

        def runner() -> None:
            async def run() -> None:
                try:
                    connection = await self._nats.connect(self._url)
                    state["connection"] = connection
                    for subject in subjects:
                        async def on_message(message: Any, _callback: Callable[..., Any] = callback) -> None:
                            _callback(message)

                        await connection.subscribe(subject, cb=on_message)
                    ready.set()
                    while not stopped.is_set():
                        await asyncio.sleep(0.05)
                    await connection.drain()
                except BaseException as error:
                    state["error"] = error
                    ready.set()

            asyncio.run(run())

        thread = threading.Thread(target=runner, name="teamusers-nats", daemon=True)
        thread.start()
        if not ready.wait(10):
            stopped.set()
            raise NATSSubscriptionError("timed out connecting to NATS")
        if "error" in state:
            stopped.set()
            raise NATSSubscriptionError("connect to NATS", state["error"])

        def close() -> None:
            stopped.set()
            thread.join(timeout=10)

        return PermissionSubscription([close])


__all__ = [
    "KEY_ROTATION_EVENT_SUBJECT",
    "TEAM_CREATED_EVENT_KIND",
    "TEAM_CREATED_EVENT_SUBJECT",
    "TEAM_UPDATED_EVENT_KIND",
    "TEAM_UPDATED_EVENT_SUBJECT",
    "USER_CREATED_EVENT_KIND",
    "USER_CREATED_EVENT_SUBJECT",
    "USER_UPDATED_EVENT_KIND",
    "USER_UPDATED_EVENT_SUBJECT",
    "TeamCreatedEvent",
    "TeamUpdatedEvent",
    "UserCreatedEvent",
    "UserUpdatedEvent",
    "SubscribeTeamCreated",
    "SubscribeTeamUpdated",
    "SubscribeUserCreated",
    "SubscribeUserUpdated",
    "subscribe_team_created",
    "subscribe_team_updated",
    "subscribe_user_created",
    "subscribe_user_updated",
    "NATSSubscriptionError",
    "NATSUnavailableError",
    "PERMISSION_EVENT_SUBJECTS",
    "PermissionSubscription",
    "SubscribeKeyRotations",
    "SubscribePermissions",
    "Subscription",
    "subscribe_key_rotations",
    "subscribe_permissions",
]

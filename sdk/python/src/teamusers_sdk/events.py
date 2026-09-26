"""Optional permission-cache invalidation events."""

from __future__ import annotations

import asyncio
import inspect
import json
import threading
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .verifier import SDKError

PERMISSION_EVENT_SUBJECTS = (
    "iam.perm.changed",
    "iam.user.disabled",
    "iam.role.updated",
)


class NATSSubscriptionError(SDKError):
    """NATS could not be loaded or a subscription could not be created."""

    code = "NATS_SUBSCRIPTION_FAILED"


class NATSUnavailableError(NATSSubscriptionError):
    """The optional nats-py package is not installed."""

    code = "NATS_DEPENDENCY_MISSING"


class PermissionSubscription:
    """A closeable permission event subscription."""

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


def _subscribe_source(source: Any, callback: Callable[..., Any]) -> PermissionSubscription:
    closers: list[Callable[[], Any]] = []
    if isinstance(source, _NATSSource):
        return source.subscribe(callback)

    subscribe = getattr(source, "subscribe", None)
    if callable(subscribe):
        for subject in PERMISSION_EVENT_SUBJECTS:
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
            result = _invoke_factory(source, callback)
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


def _invoke_factory(factory: Callable[..., Any], callback: Callable[..., Any]) -> Any:
    try:
        signature = inspect.signature(factory)
        positional = [
            parameter
            for parameter in signature.parameters.values()
            if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
        ]
        if any(parameter.kind == parameter.VAR_POSITIONAL for parameter in signature.parameters.values()) or len(positional) >= 2:
            return factory(PERMISSION_EVENT_SUBJECTS, callback)
        return factory(callback)
    except (TypeError, ValueError):
        return factory(PERMISSION_EVENT_SUBJECTS, callback)


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

    def subscribe(self, callback: Callable[..., Any]) -> PermissionSubscription:
        ready = threading.Event()
        state: dict[str, Any] = {}
        stopped = threading.Event()

        def runner() -> None:
            async def run() -> None:
                try:
                    connection = await self._nats.connect(self._url)
                    state["connection"] = connection
                    for subject in PERMISSION_EVENT_SUBJECTS:
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
    "NATSSubscriptionError",
    "NATSUnavailableError",
    "PERMISSION_EVENT_SUBJECTS",
    "PermissionSubscription",
    "SubscribePermissions",
    "Subscription",
    "subscribe_permissions",
]

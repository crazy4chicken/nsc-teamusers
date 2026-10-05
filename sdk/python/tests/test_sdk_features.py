import base64
import threading
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from teamusers_sdk import (
    Authenticate,
    CompileCondition,
    Context,
    ForbiddenError,
    KEY_ROTATION_EVENT_SUBJECT,
    MatchKeys,
    Parse,
    PermissionSubscription,
    PermissionsClient,
    Request,
    RequireFresh,
    require_fresh,
    RejectImpersonated,
    Resource,
    Subject,
    TokenClaimsError,
    UnauthorizedError,
    Verifier,
    subscribe_key_rotations,
    subscribe_user_deleted,
)


def _jwks_and_token(*, aud="teamusers", kid="test-key"):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    jwks = {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": base64.urlsafe_b64encode(public).rstrip(b"=").decode(),
                "kid": kid,
                "alg": "EdDSA",
                "use": "sig",
            }
        ]
    }
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": "teamusers",
            "sub": "usr_1",
            "aud": aud,
            "exp": now + 300,
            "kind": "user",
            "perm_ver": 1,
        },
        private,
        algorithm="EdDSA",
        headers={"kid": kid},
    )
    return jwks, token


def test_audience_array_must_contain_exactly_one_value():
    jwks, token = _jwks_and_token(aud=["teamusers", "other"])
    verifier = Verifier("https://iam.example.com", jwks=jwks)
    with pytest.raises(TokenClaimsError):
        verifier.verify(token)


def test_concurrent_jwks_fetch_is_single_flight():
    jwks, token = _jwks_and_token()
    count = 0
    lock = threading.Lock()
    started = threading.Event()

    def fetch(_url):
        nonlocal count
        with lock:
            count += 1
        started.set()
        time.sleep(0.02)
        return jwks

    verifier = Verifier("https://iam.example.com", fetcher=fetch)
    errors = []

    def run():
        try:
            verifier.verify(token)
        except Exception as error:  # pragma: no cover - assertion below reports it
            errors.append(error)

    threads = [threading.Thread(target=run) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert started.is_set()
    assert errors == []
    assert count == 1

def test_concurrent_kid_miss_refresh_is_single_flight():
    old_jwks, _ = _jwks_and_token(kid="old-key")
    new_jwks, token = _jwks_and_token(kid="new-key")
    count = 0
    lock = threading.Lock()

    def fetch(_url):
        nonlocal count
        with lock:
            count += 1
            result = old_jwks if count == 1 else new_jwks
        time.sleep(0.02)
        return result

    verifier = Verifier("https://iam.example.com", fetcher=fetch)
    errors = []

    def run():
        try:
            verifier.verify(token)
        except Exception as error:  # pragma: no cover - assertion below reports it
            errors.append(error)

    threads = [threading.Thread(target=run) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert count == 2


def test_permissions_ttl_perm_ver_and_single_flight():
    responses = {"version": 2, "perm_ver": 1, "grants": [{"key": "orders:read:team"}]}
    count = 0
    urls = []
    lock = threading.Lock()
    entered = threading.Event()

    def fetch(url, _headers):
        nonlocal count
        urls.append(url)
        with lock:
            count += 1
        entered.set()
        time.sleep(0.02)
        return {"user_id": "usr_1", **responses}

    client = PermissionsClient("https://iam.example.com", service_token="svc", ttl=0.05, fetcher=fetch)
    threads = [threading.Thread(target=lambda: client.Get("usr_1", 1)) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert entered.is_set()
    assert count == 1
    client.Get("usr_1", 1)
    assert count == 1
    responses["perm_ver"] = 2
    client.Get("usr_1", 2)
    assert count == 2
    time.sleep(0.06)
    client.Get("usr_1", 2)
    assert count == 3
    assert all(url.endswith("?version=2") for url in urls)

@pytest.mark.parametrize(
    "invalidate",
    [
        pytest.param(lambda client: client.invalidate("usr_1"), id="user"),
        pytest.param(lambda client: client.invalidate_all(), id="all"),
    ],
)
def test_permission_invalidation_fences_inflight_snapshots(invalidate):
    started = threading.Event()
    release = threading.Event()
    fetch_count = 0
    fallback_count = 0

    def request(method, _url, _headers, _body):
        nonlocal fetch_count, fallback_count
        if method == "GET":
            fetch_count += 1
            if fetch_count == 1:
                started.set()
                assert release.wait(timeout=10)
                return {
                    "version": 2,
                    "user_id": "usr_1",
                    "perm_ver": 1,
                    "grants": [{"key": "orders:read:any"}],
                }
            return {"version": 2, "user_id": "usr_1", "perm_ver": 1, "grants": []}
        fallback_count += 1
        return {"allow": True, "matched": ["orders:read:any"], "reason": "permission granted"}

    client = PermissionsClient(
        "https://iam.example.com", service_token="svc", requester=request
    )
    results = []
    errors = []

    def allow():
        try:
            results.append(tuple(client.Allow(_claims(), "orders:read:any")))
        except Exception as error:  # pragma: no cover - assertion below reports it
            errors.append(error)

    owner = threading.Thread(target=allow)
    waiter = None
    owner.start()
    try:
        assert started.wait(timeout=5)
        call = client._inflight["usr_1"]
        waiter_started = threading.Event()
        original_wait = call.done.wait

        def wait_for_owner(timeout=None):
            waiter_started.set()
            return original_wait(timeout)

        call.done.wait = wait_for_owner
        waiter = threading.Thread(target=allow)
        waiter.start()
        assert waiter_started.wait(timeout=5)
        invalidate(client)
    finally:
        release.set()
        owner.join(timeout=5)
        if waiter is not None:
            waiter.join(timeout=5)

    assert not owner.is_alive()
    assert waiter is not None and not waiter.is_alive()
    assert errors == []
    assert results == [(False, "invalid permission snapshot"), (False, "invalid permission snapshot")]
    assert fetch_count == 1
    assert fallback_count == 0
    assert client.Get("usr_1", 1).grants == ()
    assert fetch_count == 2



def test_permission_match_and_condition_subset():
    assert MatchKeys("orders:*:team", "orders:read:team")
    assert MatchKeys("!orders:read:team", "orders:read:team") is False
    condition = CompileCondition(
        'subject.id == "usr_1" && resource.attrs["tier"] == "gold" && '
        'request.time >= "2025-01-01T00:00:00Z"'
    )
    values = Context(
        subject=Subject(id="usr_1", kind="user"),
        resource=Resource(attrs={"tier": "gold"}),
        request=Request(time=datetime(2026, 1, 1, tzinfo=timezone.utc)),
    )
    assert condition.Eval(values)
    assert not condition.Eval(
        Context(
            subject=values.subject,
            resource=Resource(attrs={"tier": "silver"}),
            request=values.request,
        )
    )
    with pytest.raises(ValueError):
        CompileCondition("resource.unknown == true")

def test_permission_grammar_and_condition_fail_closed():
    valid = {
        "orders:read:team",
        "order-items.v2:read-write:own",
        "orders:*:any",
        "orders:read:*",
        "!orders:delete:own",
        "iam:teams:team",
    }
    for key in valid:
        permission = Parse(key)
        assert permission.String() == key
        permission.Validate()
    for key in ("", ":read:team", "Orders:read:team", "orders:read:tenant", "orders:read", "!!orders:read:team", "iam:users:team"):
        with pytest.raises(ValueError):
            Parse(key)
    assert MatchKeys("!orders:read:team", "!orders:read:team")
    condition_source = 'subject.kind in ["user", "service"] && !(resource.owner_id == "blocked") && 2 < 3'
    condition = CompileCondition(condition_source)
    assert condition.Eval(Context(subject=Subject(kind="user")))
    assert not condition.Eval(Context(subject=Subject(kind="unknown")))
    assert not CompileCondition('resource.attrs["missing"] > 1').Eval(Context())
    client = PermissionsClient(
        "https://iam.example.com",
        service_token="svc",
        fetcher=lambda _url: {
            "version": 2,
            "user_id": "usr_1",
            "perm_ver": 1,
            "grants": [
                {"key": "orders:read:team", "team_id": "team-a"},
                {"key": "!orders:read:team", "team_id": "team-a", "condition": condition_source},
            ],
        },
    )
    allowed_when_deny_matches = client.Allow(
        _claims(),
        "orders:read:team",
        {"team_id": "team-a", "owner_id": "eligible"},
    ).allow
    allowed_when_deny_skips = client.Allow(
        _claims(),
        "orders:read:team",
        {"team_id": "team-a", "owner_id": "blocked"},
    ).allow
    allowed_without_team_context = client.Allow(_claims(), "orders:read:team").allow
    assert allowed_when_deny_matches is False
    assert allowed_when_deny_skips is True
    assert allowed_without_team_context is False


def test_v2_permission_snapshots_fail_closed_without_remote_fallback():
    payloads = [
        {"user_id": "usr_1", "perm_ver": 1, "grants": []},
        {"version": 1, "user_id": "usr_1", "perm_ver": 1, "grants": []},
        {"version": 3, "user_id": "usr_1", "perm_ver": 1, "grants": []},
        {
            "version": 2,
            "user_id": "usr_1",
            "perm_ver": 1,
            "grants": [{"key": "orders:read:any", "condition": None}],
        },
        {
            "version": 2,
            "user_id": "usr_1",
            "perm_ver": 1,
            "grants": [{"key": "orders:read:any", "team_id": ""}],
        },
        {"version": 2, "user_id": "usr_1", "perm_ver": 1, "grants": [], "valid_until": "invalid"},
        {
            "version": 2,
            "user_id": "usr_1",
            "perm_ver": 1,
            "grants": [],
            "valid_until": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        },
    ]
    snapshot_index = 0
    fallback_count = 0
    calls = []

    def request(method, url, _headers, _body):
        nonlocal snapshot_index, fallback_count
        calls.append((method, url))
        if method == "GET":
            payload = payloads[snapshot_index]
            snapshot_index += 1
            return payload
        fallback_count += 1
        return {"allow": True, "matched": ["orders:read:any"], "reason": "permission granted"}

    client = PermissionsClient("https://iam.example.com", service_token="svc", requester=request)
    for _payload in payloads:
        assert tuple(client.Allow(_claims(), "orders:read:any", {"team_id": "team-a"})) == (
            False,
            "invalid permission snapshot",
        )
    assert snapshot_index == len(payloads)
    assert fallback_count == 0
    assert all(method == "GET" and url.endswith("?version=2") for method, url in calls)

def test_v2_snapshots_tolerate_additive_fields_and_defer_condition_compile_errors():
    payload = {
        "version": 2,
        "user_id": "usr_1",
        "perm_ver": 1,
        "future_snapshot_field": {"revision": 3},
        "grants": [
            {
                "key": "!orders:read:any",
                "condition": "subject.id",
                "team_id": "team-b",
                "future_grant_field": "ignored",
            },
            {"key": "iam:teams:any", "condition": "subject.id"},
            {"key": "orders:read:any"},
        ],
    }
    client = PermissionsClient(
        "https://iam.example.com",
        service_token="svc",
        fetcher=lambda _url: payload,
    )
    claims = _claims()

    assert tuple(client.Allow(claims, "orders:read:any", {"team_id": "team-a"})) == (
        True,
        "permission granted",
    )
    assert tuple(client.Allow(claims, "orders:read:any", {"team_id": "team-b"})) == (
        False,
        "condition_error",
    )
    assert tuple(client.Allow(claims, "orders:write:any", {"team_id": "team-b"})) == (
        False,
        "no matching grant",
    )



def test_team_scoped_permissions_isolate_teams_and_keep_platform_grants():
    claims = _claims()
    scoped = PermissionsClient(
        "https://iam.example.com",
        service_token="svc",
        fetcher=lambda _url: {
            "version": 2,
            "user_id": "usr_1",
            "perm_ver": 1,
            "grants": [
                {"key": "orders:read:any", "team_id": "team-a"},
                {"key": "!orders:read:any", "team_id": "team-b"},
            ],
        },
    )
    assert tuple(scoped.Allow(claims, "orders:read:any", {"team_id": "team-a"})) == (
        True,
        "permission granted",
    )
    assert tuple(scoped.Allow(claims, "orders:read:any", {"team_id": "team-b"})) == (
        False,
        "permission denied",
    )
    assert tuple(scoped.Allow(claims, "orders:read:any", {"team_id": "team-c"})) == (
        False,
        "no matching grant",
    )
    assert tuple(scoped.Allow(claims, "orders:read:any")) == (False, "no matching grant")
    assert scoped.Get("usr_1", 1).grants[0].team_id == "team-a"

    platform_any = PermissionsClient(
        "https://iam.example.com",
        service_token="svc",
        fetcher=lambda _url: {
            "version": 2,
            "user_id": "usr_1",
            "perm_ver": 1,
            "grants": [{"key": "orders:read:any"}],
        },
    )
    assert tuple(platform_any.Allow(claims, "orders:read:any")) == (True, "permission granted")

    platform_team = PermissionsClient(
        "https://iam.example.com",
        service_token="svc",
        fetcher=lambda _url: {
            "version": 2,
            "user_id": "usr_1",
            "perm_ver": 1,
            "grants": [{"key": "orders:read:team"}],
        },
    )
    assert tuple(platform_team.Allow(claims, "orders:read:team")) == (False, "no matching grant")
    assert tuple(
        platform_team.Allow(claims, "orders:read:team", {"team_id": "team-a"})
    ) == (True, "permission granted")


def test_condition_false_skips_and_condition_errors_deny_in_either_order():
    false_deny = {
        "key": "!orders:read:any",
        "condition": 'resource.attrs["eligible"] == true',
    }
    allow = {"key": "orders:read:any"}
    for grants in ([false_deny, allow], [allow, false_deny]):
        client = PermissionsClient(
            "https://iam.example.com",
            service_token="svc",
            fetcher=lambda _url: {
                "version": 2,
                "user_id": "usr_1",
                "perm_ver": 1,
                "grants": grants,
            },
        )
        assert tuple(
            client.Allow(_claims(), "orders:read:any", {"attrs": {"eligible": False}})
        ) == (True, "permission granted")

    error_grant = {
        "key": "orders:read:any",
        "condition": 'resource.attrs["count"] > 0',
    }
    for grants in ([error_grant, allow], [allow, error_grant]):
        client = PermissionsClient(
            "https://iam.example.com",
            service_token="svc",
            fetcher=lambda _url: {
                "version": 2,
                "user_id": "usr_1",
                "perm_ver": 1,
                "grants": grants,
            },
        )
        assert tuple(
            client.Allow(_claims(), "orders:read:any", {"attrs": {"count": "not-a-number"}})
        ) == (False, "condition_error")


def test_string_in_uses_substring_semantics_and_scalar_operands_fail_closed():
    claims = _claims()
    source = 'subject.id in resource.attrs["blocked"]'
    condition = CompileCondition(source)
    with pytest.raises(TypeError):
        condition.eval_strict(
            Context(
                subject=Subject(id="usr_1", kind="user"),
                resource=Resource(attrs={"blocked": 42}),
            )
        )

    deny = {"key": "!orders:read:any", "condition": source}
    allow = {"key": "orders:read:any"}

    def decide(grants, blocked):
        client = PermissionsClient(
            "https://iam.example.com",
            service_token="svc",
            fetcher=lambda _url: {
                "version": 2,
                "user_id": "usr_1",
                "perm_ver": 1,
                "grants": grants,
            },
        )
        return tuple(
            client.Allow(claims, "orders:read:any", {"attrs": {"blocked": blocked}})
        )

    for grants in ([deny, allow], [allow, deny]):
        assert decide(grants, "blocked:usr_1:also") == (False, "permission denied")
        assert decide(grants, "other-user") == (True, "permission granted")
    assert decide([deny, allow], 42) == (False, "condition_error")

def test_permission_cache_preserves_team_metadata_and_clamps_valid_until():
    count = 0

    def fetch(_url):
        nonlocal count
        count += 1
        return {
            "version": 2,
            "user_id": "usr_1",
            "perm_ver": 1,
            "grants": [{"key": "orders:read:any", "team_id": "team-a"}],
            "valid_until": (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat(),
        }

    client = PermissionsClient(
        "https://iam.example.com", service_token="svc", ttl=30, fetcher=fetch
    )
    first = client.Get("usr_1", 1)
    cached = client.Get("usr_1", 1)
    assert first.valid_until == cached.valid_until
    assert cached.grants[0].team_id == "team-a"
    assert count == 1

    time.sleep(1.05)
    refreshed = client.Get("usr_1", 1)
    assert refreshed.grants[0].team_id == "team-a"
    assert count == 2

def test_middleware_errors_and_event_invalidation():
    class FakeVerifier:
        def verify(self, _token):
            return claims

    claims = _claims()
    request = {"headers": {"authorization": "Bearer token"}, "method": "GET"}
    assert Authenticate(request, FakeVerifier()) == claims
    with pytest.raises(UnauthorizedError):
        Authenticate({"headers": {}}, FakeVerifier())

    fetched = 0

    def fetch(_url):
        nonlocal fetched
        fetched += 1
        return {"version": 2, "user_id": "usr_1", "perm_ver": 1, "grants": []}

    client = PermissionsClient("https://iam.example.com", service_token="svc", fetcher=fetch)
    client.Get("usr_1", 1)

    class Source:
        def __init__(self):
            self.callbacks = {}

        def subscribe(self, subject, callback):
            self.callbacks[subject] = callback

        def emit(self, subject, payload):
            self.callbacks[subject](payload)

    source = Source()
    seen = []
    subscription = client.SubscribePermissions(source, seen.append)
    source.emit("iam.perm.changed", {"user_ids": ["usr_1"]})
    client.Get("usr_1", 1)
    assert seen == [["usr_1"]]
    assert fetched == 2
    assert isinstance(subscription, PermissionSubscription)
    subscription.Close()



def test_user_deleted_lifecycle_events_do_not_require_changed_fields():
    class Source:
        def __init__(self):
            self.callbacks = {}

        def subscribe(self, subject, callback):
            self.callbacks[subject] = callback

    source = Source()
    received = []
    subscription = subscribe_user_deleted(source, received.append)
    source.callbacks["iam.user.deleted"](
        {
            "event_id": 23,
            "type": "user.deleted",
            "user_id": "usr_1",
            "at": "2026-09-30T00:00:00Z",
        }
    )
    assert received == [
        {
            "event_id": 23,
            "type": "user.deleted",
            "user_id": "usr_1",
            "at": "2026-09-30T00:00:00Z",
        }
    ]
    subscription.Close()

def test_require_fresh_accepts_auth_time_or_step_up_time():
    request = {"headers": {}, "method": "POST"}
    guard = RequireFresh(60)
    now = int(time.time())
    claims = replace(_claims(), auth_time=now, amr=("pwd", "otp"))

    assert guard(request, claims) == claims
    assert guard(request, replace(claims, auth_time=now + 30)).auth_time == now + 30
    with pytest.raises(UnauthorizedError):
        guard(request)

    fresh_step_up = replace(claims, auth_time=0, step_up_time=now)
    assert guard(request, fresh_step_up) == fresh_step_up
    future_step_up = replace(claims, auth_time=0, step_up_time=now + 30)
    assert require_fresh(60)(request, future_step_up) == future_step_up
    fresh_auth_with_expired_step_up = replace(claims, step_up_time=now - 120)
    assert guard(request, fresh_auth_with_expired_step_up) == fresh_auth_with_expired_step_up

    for auth_time in (0, now - 120, now + 31):
        with pytest.raises(ForbiddenError, match="step_up_required"):
            guard(request, replace(claims, auth_time=auth_time))
    for step_up_time in (now - 120, now + 31):
        with pytest.raises(ForbiddenError, match="step_up_required"):
            guard(request, replace(claims, auth_time=0, step_up_time=step_up_time))

    impersonated = replace(
        claims,
        auth_time=0,
        step_up_time=now,
        actor="admin_1",
        impersonated=True,
    )
    with pytest.raises(ForbiddenError, match="step_up_required"):
        guard(request, impersonated)

    actor_only_step_up = replace(
        claims,
        auth_time=0,
        step_up_time=now,
        actor="admin_1",
        impersonated=False,
    )
    with pytest.raises(ForbiddenError, match="step_up_required"):
        guard(request, actor_only_step_up)

    with pytest.raises(ForbiddenError, match="step_up_required"):
        RequireFresh(0)(request, claims)

def test_reject_impersonated_claims():
    request = {"headers": {}, "method": "GET"}
    guard = RejectImpersonated()
    claims = _claims()

    assert guard(request, claims) == claims
    with pytest.raises(UnauthorizedError):
        guard(request)

    impersonated = replace(claims, actor="admin_1", impersonated=True)
    with pytest.raises(ForbiddenError, match="impersonation_forbidden"):
        guard(request, impersonated)


def test_key_rotation_event_refreshes_verifier_jwks():
    previous_jwks, previous_token = _jwks_and_token(kid="rotation-previous")
    next_jwks, next_token = _jwks_and_token(kid="rotation-next")
    document = previous_jwks
    fetched = 0

    def fetcher(_url):
        nonlocal fetched
        fetched += 1
        return document

    verifier = Verifier("https://issuer.example.com", fetcher=fetcher)
    assert verifier.verify(previous_token).subject == "usr_1"
    assert fetched == 1

    class Source:
        def __init__(self):
            self.callbacks = {}

        def subscribe(self, subject, callback):
            self.callbacks[subject] = callback

        def emit(self, subject, payload):
            self.callbacks[subject](payload)

    source = Source()
    subscription = subscribe_key_rotations(verifier, source)
    document = {"keys": previous_jwks["keys"] + next_jwks["keys"]}
    source.emit(KEY_ROTATION_EVENT_SUBJECT, {"kid": "rotation-next"})

    assert fetched == 2
    assert verifier.verify(next_token).subject == "usr_1"
    assert fetched == 2
    assert subscription is not None
    subscription.close()


def _claims():
    from teamusers_sdk import Claims

    return Claims(
        subject="usr_1",
        team="",
        kind="user",
        perm_ver=1,
        expiry=datetime.now(timezone.utc) + timedelta(minutes=5),
        audience="teamusers",
    )



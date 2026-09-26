import base64
import threading
import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from teamusers_sdk import (
    Authenticate,
    CompileCondition,
    Context,
    Parse,
    MatchKeys,
    PermissionSubscription,
    PermissionsClient,
    Resource,
    Subject,
    Request,
    TokenClaimsError,
    UnauthorizedError,
    Verifier,
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
    responses = {"perm_ver": 1, "grants": [{"key": "orders:read:team"}]}
    count = 0
    lock = threading.Lock()
    entered = threading.Event()

    def fetch(_url, _headers):
        nonlocal count
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
    condition = CompileCondition('subject.kind in ["user", "service"] && !(resource.owner_id == "blocked") && 2 < 3')
    assert condition.Eval(Context(subject=Subject(kind="user")))
    assert not condition.Eval(Context(subject=Subject(kind="unknown")))
    assert not CompileCondition('resource.attrs["missing"] > 1').Eval(Context())
    client = PermissionsClient(
        "https://iam.example.com",
        service_token="svc",
        fetcher=lambda _url: {
            "user_id": "usr_1",
            "perm_ver": 1,
            "grants": [
                {"key": "orders:read:team"},
                {"key": "!orders:read:team"},
            ],
        },
    )
    assert tuple(client.Allow(_claims(), "orders:read:team")) == (False, "permission denied")


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
        return {"user_id": "usr_1", "perm_ver": 1, "grants": []}

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



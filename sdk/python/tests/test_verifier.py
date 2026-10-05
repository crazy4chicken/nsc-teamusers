import base64
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from teamusers_sdk import (
    Claims,
    JWKSFetchError,
    TokenClaimsError,
    TokenVerificationError,
    Verifier,
)


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _fixture() -> tuple[Ed25519PrivateKey, dict[str, object]]:
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return private_key, {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": _base64url(public_bytes),
                "kid": "test-key",
                "alg": "EdDSA",
                "use": "sig",
            }
        ]
    }


def _token(private_key: Ed25519PrivateKey, **claims: object) -> str:
    now = int(time.time())
    payload = {
        "iss": "teamusers",
        "sub": "sdk-user",
        "aud": "teamusers",
        "kind": "user",
        "perm_ver": 2,
        "iat": now,
        "exp": now + 300,
        **claims,
    }
    return jwt.encode(
        payload,
        private_key,
        algorithm="EdDSA",
        headers={"kid": "test-key"},
    )


def test_verifies_token_and_caches_jwks() -> None:
    private_key, jwks = _fixture()
    requests: list[str] = []

    def fetcher(url: str) -> dict[str, object]:
        requests.append(url)
        return jwks

    verifier = Verifier("https://issuer.example/", fetcher=fetcher)
    auth_time = int(time.time()) - 12
    step_up_time = int(time.time()) - 5
    claims = verifier.verify(
        _token(
            private_key,
            team="platform",
            auth_time=auth_time,
            step_up_time=step_up_time,
            amr=["pwd", "otp"],
            act={"sub": "sdk-admin"},
            imp=True,
        )
    )

    assert isinstance(claims, Claims)
    assert claims.subject == "sdk-user"
    assert claims.sub == "sdk-user"
    assert claims.team == "platform"
    assert claims.kind == "user"
    assert claims.perm_ver == 2
    assert claims.permVer == 2
    assert claims.audience == "teamusers"
    assert claims.auth_time == auth_time
    assert claims.authTime == auth_time
    assert claims.step_up_time == step_up_time
    assert claims.stepUpTime == step_up_time
    assert claims.amr == ("pwd", "otp")
    assert claims.actor == "sdk-admin"
    assert claims.impersonated is True
    assert requests == ["https://issuer.example/.well-known/jwks.json"]

    legacy = verifier.verify(_token(private_key))
    assert legacy.subject == "sdk-user"
    assert legacy.auth_time == 0
    assert legacy.step_up_time == 0
    assert legacy.stepUpTime == 0
    assert legacy.amr == ()
    assert legacy.actor is None
    assert legacy.impersonated is False

    auth_time_only = verifier.verify(_token(private_key, auth_time=auth_time))
    assert auth_time_only.auth_time == auth_time
    assert auth_time_only.step_up_time == 0


def test_expected_audience_and_claim_validation() -> None:
    private_key, jwks = _fixture()
    verifier = Verifier("https://issuer.example", "orders", jwks=jwks)

    with pytest.raises(TokenVerificationError):
        verifier.verify(_token(private_key, aud="other"))

    valid = verifier.verify(_token(private_key, aud="orders", kind="service", perm_ver=0))
    assert valid.kind == "service"
    assert valid.perm_ver == 0

    with pytest.raises(TokenClaimsError):
        verifier.verify(_token(private_key, aud="orders", kind="unknown"))
    with pytest.raises(TokenClaimsError):
        verifier.verify(_token(private_key, aud="orders", perm_ver=-1))

    for invalid_claims in (
        {"auth_time": -1},
        {"auth_time": True},
        {"step_up_time": -1},
        {"step_up_time": True},
        {"step_up_time": "123"},
        {"step_up_time": 123.5},
        {"step_up_time": 10**400},
        {"amr": "pwd"},
        {"amr": ["pwd", 1]},
        {"act": "sdk-admin"},
        {"act": {"sub": "sdk-admin"}, "imp": "true"},
        {"imp": True},
    ):
        with pytest.raises(TokenClaimsError):
            verifier.verify(_token(private_key, aud="orders", **invalid_claims))


def test_signature_and_expiration_fail_with_typed_errors() -> None:
    private_key, jwks = _fixture()
    verifier = Verifier("https://issuer.example", jwks=jwks)
    token = _token(private_key)
    parts = token.split(".")
    parts[2] = (parts[2][:-1] + ("A" if parts[2][-1] != "A" else "B"))
    with pytest.raises(TokenVerificationError):
        verifier.verify(".".join(parts))

    with pytest.raises(TokenVerificationError):
        verifier.verify(_token(private_key, exp=int(time.time()) - 1))


def test_jwks_fetch_errors_are_typed() -> None:
    private_key, _ = _fixture()

    def fetcher(_: str) -> dict[str, object]:
        raise OSError("offline")

    verifier = Verifier("https://issuer.example", fetcher=fetcher)
    with pytest.raises(JWKSFetchError):
        verifier.verify(_token(private_key))

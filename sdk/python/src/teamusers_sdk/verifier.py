"""Teamusers access-token verification."""

from __future__ import annotations

import json
import math
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, TypeAlias
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import jwt
from jwt import PyJWK

DEFAULT_ISSUER = "teamusers"
DEFAULT_AUDIENCE = "teamusers"
DEFAULT_CACHE_TTL_SECONDS = 60 * 60

TokenKind: TypeAlias = Literal["user", "service"]
Audience: TypeAlias = str | tuple[str, ...]
JWKSFetcher: TypeAlias = Callable[[str], Mapping[str, Any]]


class SDKError(Exception):
    """Base class for errors raised by this SDK."""

    code = "SDK_ERROR"

    def __init__(self, message: str, cause: BaseException | None = None) -> None:
        super().__init__(message)
        self.cause = cause


class VerifierConfigError(SDKError):
    """The verifier was configured with an unusable value."""

    code = "INVALID_VERIFIER_CONFIGURATION"


class JWKSFetchError(SDKError):
    """The JWKS endpoint did not return a usable key set."""

    code = "JWKS_FETCH_FAILED"


class TokenVerificationError(SDKError):
    """The token failed JOSE authentication or required claim validation."""

    code = "TOKEN_VERIFICATION_FAILED"


class TokenClaimsError(TokenVerificationError):
    """A verified token carried invalid application claims."""

    code = "TOKEN_CLAIMS_INVALID"


# Descriptive aliases for applications that use shorter names.
TeamusersError = SDKError
InvalidTokenError = TokenVerificationError
InvalidClaimsError = TokenClaimsError


@dataclass(frozen=True, slots=True)
class Claims:
    """Identity claims carried by a successfully verified access token."""

    subject: str
    team: str
    kind: TokenKind
    perm_ver: int
    expiry: datetime
    audience: Audience

    @property
    def sub(self) -> str:
        """JWT ``sub`` spelling."""

        return self.subject

    @property
    def permVer(self) -> int:
        """Camel-case spelling of ``perm_ver`` for cross-SDK callers."""

        return self.perm_ver

    @property
    def exp(self) -> float:
        """JWT expiration as a Unix timestamp in seconds."""

        return self.expiry.timestamp()

    @property
    def aud(self) -> Audience:
        """JWT ``aud`` spelling."""

        return self.audience


@dataclass(frozen=True, slots=True)
class _CachedKeys:
    keys: tuple[PyJWK, ...]
    expires_at: float


class Verifier:
    """Verify teamusers Ed25519 access tokens against a cached JWKS document.

    The JWKS URL is derived from ``base_url`` and is fetched lazily on the first
    call to :meth:`verify`. ``fetcher`` and ``jwks`` are dependency-injection
    seams for applications with a custom HTTP transport and deterministic tests.
    """

    def __init__(
        self,
        base_url: str,
        audience: str = DEFAULT_AUDIENCE,
        *,
        expected_audience: str | None = None,
        cache_ttl: float = DEFAULT_CACHE_TTL_SECONDS,
        cache_ttl_seconds: float | None = None,
        fetcher: JWKSFetcher | None = None,
        fetch: JWKSFetcher | None = None,
        jwks: Mapping[str, Any] | None = None,
    ) -> None:
        self._config_error: VerifierConfigError | None = None
        base = base_url.strip().rstrip("/")
        parsed = urlparse(base)
        if not base or not parsed.scheme or not parsed.netloc:
            self._config_error = VerifierConfigError(
                "invalid verifier base URL: URL must include scheme and host"
            )
            self._jwks_url = ""
        else:
            self._jwks_url = f"{base}/.well-known/jwks.json"

        configured_audience = expected_audience if expected_audience is not None else audience
        if not isinstance(configured_audience, str) or not configured_audience.strip():
            self._config_error = VerifierConfigError("expected audience is empty")
            configured_audience = DEFAULT_AUDIENCE
        self._audience = configured_audience

        configured_ttl = cache_ttl_seconds if cache_ttl_seconds is not None else cache_ttl
        if not isinstance(configured_ttl, (int, float)) or isinstance(configured_ttl, bool):
            self._config_error = VerifierConfigError(
                "JWKS cache TTL must be a finite non-negative number"
            )
            configured_ttl = DEFAULT_CACHE_TTL_SECONDS
        elif not math.isfinite(float(configured_ttl)) or configured_ttl < 0:
            self._config_error = VerifierConfigError(
                "JWKS cache TTL must be a finite non-negative number"
            )
            configured_ttl = DEFAULT_CACHE_TTL_SECONDS
        self._cache_ttl = float(configured_ttl)

        self._fetcher = fetcher or fetch or _default_fetcher
        self._static_keys: tuple[PyJWK, ...] | None = None
        self._cache: _CachedKeys | None = None
        if jwks is not None:
            try:
                self._static_keys = _parse_jwks(jwks)
            except JWKSFetchError as error:
                self._config_error = VerifierConfigError("invalid in-memory JWKS", error)

    @property
    def jwks_url(self) -> str:
        """The endpoint used to obtain signing keys."""

        return self._jwks_url

    def close(self) -> None:
        """Release verifier resources; retained for parity with the Go SDK."""

    def verify(self, raw: str) -> Claims:
        """Authenticate a compact JWT and return its typed identity claims."""

        if self._config_error is not None:
            raise self._config_error
        if not isinstance(raw, str) or not raw.strip():
            raise TokenVerificationError("access token is empty")

        try:
            header = jwt.get_unverified_header(raw)
        except jwt.PyJWTError as error:
            raise TokenVerificationError("decode access token header", error) from error
        if header.get("alg") != "EdDSA":
            raise TokenVerificationError("access token algorithm must be EdDSA")
        kid = header.get("kid")
        if kid is not None and not isinstance(kid, str):
            raise TokenVerificationError("access token key id is invalid")

        keys = self._get_keys()
        candidates = _select_keys(keys, kid)
        if not candidates and self._static_keys is None:
            keys = self._get_keys(force_refresh=True)
            candidates = _select_keys(keys, kid)
        if not candidates:
            raise TokenVerificationError("no matching EdDSA key in JWKS")

        payload = _decode_with_candidates(raw, candidates, self._audience)
        return _claims_from_payload(payload, self._audience)

    def _get_keys(self, force_refresh: bool = False) -> tuple[PyJWK, ...]:
        if self._static_keys is not None:
            return self._static_keys

        now = time.monotonic()
        if not force_refresh and self._cache is not None and self._cache.expires_at > now:
            return self._cache.keys

        try:
            document = self._fetcher(self._jwks_url)
        except SDKError:
            raise
        except Exception as error:
            raise JWKSFetchError("fetch JWKS", error) from error

        keys = _parse_jwks(document)
        self._cache = _CachedKeys(keys=keys, expires_at=now + self._cache_ttl)
        return keys


def _default_fetcher(url: str) -> Mapping[str, Any]:
    request = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=10) as response:
            status = getattr(response, "status", 200)
            if not 200 <= status < 300:
                raise JWKSFetchError(f"fetch JWKS: HTTP {status}")
            value = json.load(response)
    except JWKSFetchError:
        raise
    except (OSError, URLError, ValueError) as error:
        raise JWKSFetchError("fetch JWKS", error) from error
    if not isinstance(value, Mapping):
        raise JWKSFetchError("decode JWKS response: object expected")
    return value


def _parse_jwks(document: Mapping[str, Any]) -> tuple[PyJWK, ...]:
    if not isinstance(document, Mapping):
        raise JWKSFetchError("decode JWKS response: object expected")
    raw_keys = document.get("keys")
    if not isinstance(raw_keys, Sequence) or isinstance(raw_keys, (str, bytes, bytearray)):
        raise JWKSFetchError("decode JWKS response: keys must be an array")

    keys: list[PyJWK] = []
    for raw_key in raw_keys:
        if not isinstance(raw_key, Mapping):
            continue
        if raw_key.get("alg") not in (None, "EdDSA"):
            continue
        if raw_key.get("use") not in (None, "sig"):
            continue
        key_ops = raw_key.get("key_ops")
        if key_ops is not None and (
            not isinstance(key_ops, Sequence)
            or isinstance(key_ops, (str, bytes, bytearray))
            or "verify" not in key_ops
        ):
            continue
        if raw_key.get("kty") != "OKP" or raw_key.get("crv") != "Ed25519":
            continue
        try:
            key = PyJWK.from_dict(dict(raw_key))
        except Exception:
            continue
        if key.algorithm_name == "EdDSA":
            keys.append(key)
    if not keys:
        raise JWKSFetchError("decode JWKS response: no Ed25519 signing keys")
    return tuple(keys)


def _select_keys(keys: Sequence[PyJWK], kid: str | None) -> list[PyJWK]:
    if kid is None:
        return list(keys)
    return [key for key in keys if key.key_id == kid]


def _decode_with_candidates(
    raw: str,
    candidates: Sequence[PyJWK],
    audience: str,
) -> Mapping[str, Any]:
    last_error: BaseException | None = None
    for candidate in candidates:
        try:
            payload = jwt.decode(
                raw,
                candidate.key,
                algorithms=["EdDSA"],
                issuer=DEFAULT_ISSUER,
                audience=audience,
                options={
                    "require": ["exp", "iss", "sub", "aud", "kind", "perm_ver"],
                },
            )
        except jwt.PyJWTError as error:
            last_error = error
            if isinstance(
                error,
                (
                    jwt.InvalidSignatureError,
                    jwt.InvalidKeyError,
                ),
            ):
                continue
            raise TokenVerificationError("verify access token", error) from error
        if isinstance(payload, Mapping):
            return payload
        raise TokenVerificationError("access token payload is not an object")

    raise TokenVerificationError("verify access token", last_error) from last_error


def _claims_from_payload(payload: Mapping[str, Any], expected_audience: str) -> Claims:
    if payload.get("iss") != DEFAULT_ISSUER:
        raise TokenClaimsError("invalid access token issuer")

    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        raise TokenClaimsError("access token subject is missing")

    expiry_raw = payload.get("exp")
    if (
        isinstance(expiry_raw, bool)
        or not isinstance(expiry_raw, (int, float))
        or not math.isfinite(float(expiry_raw))
        or float(expiry_raw) <= time.time()
    ):
        raise TokenClaimsError("access token is expired or has no expiration")
    expiry = datetime.fromtimestamp(float(expiry_raw), tz=timezone.utc)

    audience_raw = payload.get("aud")
    audience_values = _normalize_audience(audience_raw)
    if audience_values is None or expected_audience not in audience_values:
        raise TokenClaimsError("invalid access token audience")

    kind = payload.get("kind")
    if kind not in ("user", "service"):
        raise TokenClaimsError("invalid access token kind")

    perm_ver_raw = payload.get("perm_ver")
    if (
        isinstance(perm_ver_raw, bool)
        or not isinstance(perm_ver_raw, (int, float))
        or not math.isfinite(float(perm_ver_raw))
        or int(perm_ver_raw) != perm_ver_raw
        or perm_ver_raw < 0
    ):
        raise TokenClaimsError("invalid access token perm_ver")

    team = payload.get("team", "")
    if not isinstance(team, str):
        raise TokenClaimsError("invalid access token team")

    audience: Audience = (
        tuple(audience_values) if isinstance(audience_raw, list) else audience_values[0]
    )
    return Claims(
        subject=subject,
        team=team,
        kind=kind,
        perm_ver=int(perm_ver_raw),
        expiry=expiry,
        audience=audience,
    )


def _normalize_audience(value: Any) -> list[str] | None:
    if isinstance(value, str):
        return [value] if value else None
    if isinstance(value, list) and value and all(
        isinstance(entry, str) and bool(entry) for entry in value
    ):
        return list(value)
    return None

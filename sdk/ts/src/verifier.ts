import { createLocalJWKSet, jwtVerify } from "jose";
import type { JSONWebKeySet as JoseJSONWebKeySet, LocalJWKSet } from "jose";

const DEFAULT_ISSUER = "teamusers";
const DEFAULT_AUDIENCE = "teamusers";
const DEFAULT_CACHE_TTL_MS = 60 * 60 * 1000;

type JoseJWKS = JoseJSONWebKeySet;

/** A JSON response with the subset needed by the verifier's JWKS loader. */
export interface JWKSResponse {
  readonly ok: boolean;
  readonly status: number;
  json(): Promise<unknown>;
}

/** Injectable fetch function, useful for tests and custom HTTP transports. */
export type JWKSFetcher = (url: string) => Promise<JWKSResponse>;

export interface JSONWebKeySet {
  readonly keys: readonly Record<string, unknown>[];
}

export interface VerifierOptions {
  /** Expected JWT audience. Defaults to `teamusers`. */
  readonly audience?: string;
  /** Alias for `audience`. */
  readonly expectedAudience?: string;
  /** JWKS cache lifetime in milliseconds. Defaults to one hour. */
  readonly cacheTtlMs?: number;
  /** Alias for `cacheTtlMs`. */
  readonly ttlMs?: number;
  /** Custom JWKS transport. Defaults to global `fetch`. */
  readonly fetch?: JWKSFetcher;
  /** Alias for `fetch`. */
  readonly fetcher?: JWKSFetcher;
  /** Optional in-memory JWKS, intended for deterministic tests. */
  readonly jwks?: JSONWebKeySet;
}

export type TokenKind = "user" | "service";
export type Audience = string | readonly string[];

/** Identity claims carried by a successfully verified access token. */
export class Claims {
  public readonly subject: string;
  public readonly team: string;
  public readonly kind: TokenKind;
  public readonly permVer: number;
  public readonly expiry: Date;
  public readonly audience: Audience;

  public constructor(values: {
    readonly subject: string;
    readonly team: string;
    readonly kind: TokenKind;
    readonly permVer: number;
    readonly expiry: Date;
    readonly audience: Audience;
  }) {
    this.subject = values.subject;
    this.team = values.team;
    this.kind = values.kind;
    this.permVer = values.permVer;
    this.expiry = values.expiry;
    this.audience = values.audience;
  }

  /** JWT `sub` spelling for callers working directly with token claims. */
  public get sub(): string {
    return this.subject;
  }

  /** JWT `perm_ver` spelling for callers working directly with token claims. */
  public get perm_ver(): number {
    return this.permVer;
  }

  /** JWT expiration as a Unix timestamp in seconds. */
  public get exp(): number {
    return this.expiry.getTime() / 1000;
  }

  /** JWT `aud` spelling for callers working directly with token claims. */
  public get aud(): Audience {
    return this.audience;
  }
}

export type ErrorCode =
  | "INVALID_VERIFIER_CONFIGURATION"
  | "JWKS_FETCH_FAILED"
  | "TOKEN_EMPTY"
  | "TOKEN_VERIFICATION_FAILED"
  | "TOKEN_CLAIMS_INVALID"
  | "UNAUTHORIZED"
  | "FORBIDDEN"
  | "PERMISSION_FETCH_FAILED"
  | "AUTHORIZATION_FAILED"
  | "NATS_UNAVAILABLE";

/** Base class for all errors raised by this SDK. */
export class SDKError extends Error {
  public readonly code: ErrorCode;

  public constructor(code: ErrorCode, message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = new.target.name;
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** The verifier could not be configured with a usable base URL or options. */
export class VerifierConfigError extends SDKError {
  public constructor(message: string, cause?: unknown) {
    super("INVALID_VERIFIER_CONFIGURATION", message, cause);
  }
}

/** The JWKS endpoint did not return a usable key set. */
export class JWKSFetchError extends SDKError {
  public constructor(message: string, cause?: unknown) {
    super("JWKS_FETCH_FAILED", message, cause);
  }
}

/** The token could not be authenticated with EdDSA or its JOSE claims failed. */
export class TokenVerificationError extends SDKError {
  public constructor(message: string, cause?: unknown) {
    super("TOKEN_VERIFICATION_FAILED", message, cause);
  }
}

/** A cryptographically valid token carried invalid or incomplete application claims. */
export class TokenClaimsError extends TokenVerificationError {
  public readonly code = "TOKEN_CLAIMS_INVALID" as const;

  public constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = new.target.name;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// Descriptive aliases for applications that use the shorter error names.
export { SDKError as TeamusersError };
export { TokenVerificationError as InvalidTokenError };
export { TokenClaimsError as InvalidClaimsError };

interface CacheEntry {
  readonly keySet: LocalJWKSet;
  readonly expiresAt: number;
}

/**
 * Verifies teamusers Ed25519 access tokens against a cached JWKS document.
 *
 * Construction is lazy: the JWKS endpoint is not contacted until `verify` is
 * called. A custom fetcher or in-memory key set can be supplied for tests.
 */
export class Verifier {
  private readonly jwksURL: string;
  private readonly expectedAudience: string;
  private readonly cacheTtlMs: number;
  private readonly fetcher: JWKSFetcher;
  private readonly staticKeySet?: LocalJWKSet;
  private readonly configError?: VerifierConfigError;
  private cache?: CacheEntry;
  private inFlightKeySet?: Promise<LocalJWKSet>;

  public constructor(baseURL: string, options?: VerifierOptions | string) {
    const resolvedOptions: VerifierOptions =
      typeof options === "string" ? { audience: options } : options ?? {};
    const base = baseURL.trim().replace(/\/+$/, "");

    let parsedBase: URL | undefined;
    try {
      parsedBase = new URL(base);
      if (parsedBase.protocol === "" || parsedBase.host === "") {
        throw new Error("URL must include scheme and host");
      }
    } catch (error) {
      this.configError = new VerifierConfigError("invalid verifier base URL", error);
      this.jwksURL = "";
      this.expectedAudience = DEFAULT_AUDIENCE;
      this.cacheTtlMs = DEFAULT_CACHE_TTL_MS;
      this.fetcher = async () => {
        throw this.configError;
      };
      return;
    }

    const configuredAudience =
      resolvedOptions.audience ?? resolvedOptions.expectedAudience ?? DEFAULT_AUDIENCE;
    if (configuredAudience.trim() === "") {
      this.configError = new VerifierConfigError("expected audience is empty");
    }
    this.expectedAudience = configuredAudience;
    this.jwksURL = `${parsedBase.toString().replace(/\/$/, "")}/.well-known/jwks.json`;

    const configuredTTL = resolvedOptions.cacheTtlMs ?? resolvedOptions.ttlMs ?? DEFAULT_CACHE_TTL_MS;
    if (!Number.isFinite(configuredTTL) || configuredTTL < 0) {
      this.configError = new VerifierConfigError("JWKS cache TTL must be a finite non-negative number");
      this.cacheTtlMs = DEFAULT_CACHE_TTL_MS;
    } else {
      this.cacheTtlMs = configuredTTL;
    }

    this.fetcher =
      resolvedOptions.fetcher ??
      resolvedOptions.fetch ??
      (async (url: string) => globalThis.fetch(url));

    if (resolvedOptions.jwks !== undefined) {
      try {
        this.staticKeySet = createLocalJWKSet(toJoseJWKS(resolvedOptions.jwks));
      } catch (error) {
        this.configError = new VerifierConfigError("invalid in-memory JWKS", error);
      }
    }
  }

  /** Release verifier resources; retained for parity with the Go SDK. */
  public close(): void {}

  /** Verify a compact JWT and return its typed teamusers identity claims. */
  public async verify(raw: string): Promise<Claims> {
    if (this.configError !== undefined) {
      throw this.configError;
    }
    if (raw.trim() === "") {
      throw new TokenVerificationError("access token is empty");
    }

    let keySet = await this.getKeySet();
    let verified: Awaited<ReturnType<typeof jwtVerify>>;
    try {
      verified = await this.verifyWithKeySet(raw, keySet);
    } catch (error) {
      if (!isNoMatchingKeyError(error)) {
        throw new TokenVerificationError("verify access token", error);
      }
      keySet = await this.getKeySet(true);
      try {
        verified = await this.verifyWithKeySet(raw, keySet);
      } catch (retryError) {
        throw new TokenVerificationError("verify access token", retryError);
      }
    }

    return claimsFromPayload(verified.payload, this.expectedAudience);
  }

  private async verifyWithKeySet(raw: string, keySet: LocalJWKSet) {
    return jwtVerify(raw, keySet, {
      algorithms: ["EdDSA"],
      issuer: DEFAULT_ISSUER,
      audience: this.expectedAudience,
    });
  }

  private async getKeySet(forceRefresh = false): Promise<LocalJWKSet> {
    if (this.staticKeySet !== undefined) {
      return this.staticKeySet;
    }
    const now = Date.now();
    if (!forceRefresh && this.cache !== undefined && this.cache.expiresAt > now) {
      return this.cache.keySet;
    }

    // A single promise covers both ordinary expiry loads and forced key-miss
    // refreshes. This prevents a burst of verifications from stampeding JWKS.
    if (this.inFlightKeySet !== undefined) {
      return this.inFlightKeySet;
    }

    const fetchPromise = this.fetchAndCacheKeySet();
    this.inFlightKeySet = fetchPromise;
    try {
      return await fetchPromise;
    } finally {
      if (this.inFlightKeySet === fetchPromise) {
        this.inFlightKeySet = undefined;
      }
    }
  }

  private async fetchAndCacheKeySet(): Promise<LocalJWKSet> {
    let response: JWKSResponse;
    try {
      response = await this.fetcher(this.jwksURL);
    } catch (error) {
      if (error instanceof JWKSFetchError) {
        throw error;
      }
      throw new JWKSFetchError("fetch JWKS", error);
    }
    if (!response.ok) {
      throw new JWKSFetchError(`fetch JWKS: HTTP ${response.status}`);
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch (error) {
      throw new JWKSFetchError("decode JWKS response", error);
    }
    if (!isJSONWebKeySet(body)) {
      throw new JWKSFetchError("decode JWKS response: keys must be an array");
    }

    let keySet: LocalJWKSet;
    try {
      keySet = createLocalJWKSet(toJoseJWKS(body));
    } catch (error) {
      throw new JWKSFetchError("create JWKS key set", error);
    }
    this.cache = { keySet, expiresAt: Date.now() + this.cacheTtlMs };
    return keySet;
  }
}

function toJoseJWKS(value: JSONWebKeySet): JoseJWKS {
  return value as unknown as JoseJWKS;
}

function isJSONWebKeySet(value: unknown): value is JSONWebKeySet {
  if (typeof value !== "object" || value === null || !("keys" in value)) {
    return false;
  }
  return Array.isArray(value.keys);
}

function claimsFromPayload(
  payload: Record<string, unknown>,
  expectedAudience: string,
): Claims {
  if (payload.iss !== DEFAULT_ISSUER) {
    throw new TokenClaimsError("invalid access token issuer");
  }
  if (typeof payload.sub !== "string" || payload.sub === "") {
    throw new TokenClaimsError("access token subject is missing");
  }

  const expiry = payload.exp;
  if (typeof expiry !== "number" || !Number.isFinite(expiry) || expiry <= Date.now() / 1000) {
    throw new TokenClaimsError("access token is expired or has no expiration");
  }

  const audience = payload.aud;
  const audienceValues = normalizeAudience(audience);
  if (audienceValues === undefined || audienceValues.length !== 1 || audienceValues[0] !== expectedAudience) {
    throw new TokenClaimsError("invalid access token audience");
  }

  const kind = payload.kind;
  if (kind !== "user" && kind !== "service") {
    throw new TokenClaimsError("invalid access token kind");
  }

  const permVer = payload.perm_ver;
  if (
    typeof permVer !== "number" ||
    !Number.isSafeInteger(permVer) ||
    permVer < 0
  ) {
    throw new TokenClaimsError("invalid access token perm_ver");
  }

  let team = "";
  if (payload.team !== undefined) {
    if (typeof payload.team !== "string") {
      throw new TokenClaimsError("invalid access token team");
    }
    team = payload.team;
  }

  return new Claims({
    subject: payload.sub,
    team,
    kind,
    permVer,
    expiry: new Date(expiry * 1000),
    audience: Array.isArray(audience) ? [...audienceValues] : audienceValues[0],
  });
}

function normalizeAudience(value: unknown): string[] | undefined {
  if (typeof value === "string") {
    return value === "" ? undefined : [value];
  }
  if (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every((entry): entry is string => typeof entry === "string" && entry !== "")
  ) {
    return [...value];
  }
  return undefined;
}

function isNoMatchingKeyError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: unknown }).code === "ERR_JWKS_NO_MATCHING_KEY"
  );
}

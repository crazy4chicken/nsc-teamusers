import {
  SDKError,
  TokenVerificationError,
  type Claims,
  type Verifier,
} from "./verifier.js";
import type { Resource } from "./abac.js";

/** Minimal request shape required by the SDK middleware helpers. */
export interface MiddlewareRequest {
  readonly headers?: Headers | Readonly<Record<string, string | readonly string[] | undefined>>;
  readonly method?: string;
  readonly [key: string]: unknown;
}

export class UnauthorizedError extends SDKError {
  public readonly status = 401;
  public readonly statusCode = 401;

  public constructor(message = "authentication is required", cause?: unknown) {
    super("UNAUTHORIZED", message, cause);
  }
}

export class ForbiddenError extends SDKError {
  public readonly status = 403;
  public readonly statusCode = 403;

  public constructor(message = "permission denied", cause?: unknown) {
    super("FORBIDDEN", message, cause);
  }
}

export interface AuthorizerLike {
  readonly verifier?: Verifier;
  allow(
    claims: Claims,
    permission: string,
    resource?: Resource,
    signal?: AbortSignal,
  ): Promise<{ allow: boolean; reason: string }>;
}

/** Extract and verify a bearer token from a minimal request object. */
export async function authenticateRequest(
  request: MiddlewareRequest,
  verifier: Pick<Verifier, "verify">,
): Promise<Claims> {
  const raw = bearerToken(headerValue(request.headers, "authorization"));
  if (raw === undefined) {
    throw new UnauthorizedError("bearer token is required");
  }
  try {
    return await verifier.verify(raw);
  } catch (error) {
    if (error instanceof UnauthorizedError) throw error;
    throw new UnauthorizedError("authentication failed", error);
  }
}

/** Go-style Authenticate helper; accepts either (request, verifier) or (verifier, request). */
export async function Authenticate(
  first: MiddlewareRequest | Pick<Verifier, "verify">,
  second: MiddlewareRequest | Pick<Verifier, "verify">,
): Promise<Claims> {
  if (isVerifier(first)) {
    return authenticateRequest(second as MiddlewareRequest, first);
  }
  return authenticateRequest(first, second as Pick<Verifier, "verify">);
}

export const authenticate = Authenticate;
export const AuthenticateRequest = authenticateRequest;

/** Create a permission middleware function for a request pipeline. */
export function requirePermission(
  authorizer: AuthorizerLike,
  permission: string,
  resourceFrom?: Resource | ((request: MiddlewareRequest) => Resource | Promise<Resource>),
): (request: MiddlewareRequest, claims?: Claims) => Promise<Claims> {
  return async (request: MiddlewareRequest, providedClaims?: Claims): Promise<Claims> => {
    const claims = providedClaims ?? await authenticateFromAuthorizer(request, authorizer);
    const resource = typeof resourceFrom === "function"
      ? await resourceFrom(request)
      : resourceFrom ?? {};
    let decision: { allow: boolean; reason: string };
    try {
      decision = await authorizer.allow(claims, permission, resource);
    } catch (error) {
      throw new ForbiddenError("authorization failed", error);
    }
    if (!decision.allow) {
      throw new ForbiddenError(decision.reason || "permission denied");
    }
    return claims;
  };
}

/** Go-style Require helper; supports a factory or direct request invocation. */
export function Require(
  authorizer: AuthorizerLike,
  permission: string,
  resourceFrom?: Resource | ((request: MiddlewareRequest) => Resource | Promise<Resource>),
): (request: MiddlewareRequest, claims?: Claims) => Promise<Claims>;
export function Require(
  authorizer: AuthorizerLike,
  request: MiddlewareRequest,
  claims: Claims | undefined,
  permission: string,
  resource?: Resource,
): Promise<Claims>;
export function Require(
  authorizer: AuthorizerLike,
  second: string | MiddlewareRequest,
  third?: Resource | ((request: MiddlewareRequest) => Resource | Promise<Resource>) | Claims,
  fourth?: string,
  fifth?: Resource,
): ((request: MiddlewareRequest, claims?: Claims) => Promise<Claims>) | Promise<Claims> {
  if (typeof second === "string") {
    return requirePermission(authorizer, second, third as Resource | ((request: MiddlewareRequest) => Resource | Promise<Resource>) | undefined);
  }
  if (fourth === undefined) {
    throw new TypeError("permission is required");
  }
  return requirePermission(authorizer, fourth, fifth)(second, third as Claims | undefined);
}

function bearerToken(header: string | undefined): string | undefined {
  if (header === undefined) return undefined;
  const parts = header.trim().split(/\s+/u);
  if (parts.length !== 2 || parts[0].toLowerCase() !== "bearer" || parts[1] === "") return undefined;
  return parts[1];
}

function headerValue(
  headers: Headers | Readonly<Record<string, string | readonly string[] | undefined>> | undefined,
  name: string,
): string | undefined {
  if (headers === undefined) return undefined;
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== name) continue;
    if (typeof value === "string") return value;
    if (Array.isArray(value)) return value.join(",");
    return undefined;
  }
  return undefined;
}

async function authenticateFromAuthorizer(
  request: MiddlewareRequest,
  authorizer: AuthorizerLike,
): Promise<Claims> {
  if (authorizer.verifier === undefined) {
    throw new UnauthorizedError("authentication verifier unavailable");
  }
  return authenticateRequest(request, authorizer.verifier);
}

function isVerifier(value: unknown): value is Pick<Verifier, "verify"> {
  return typeof value === "object" && value !== null && "verify" in value && typeof value.verify === "function";
}
export { UnauthorizedError as AuthenticationError };
export { ForbiddenError as AuthorizationError };
export { TokenVerificationError };

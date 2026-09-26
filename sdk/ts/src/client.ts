import { type Claims, Verifier } from "./verifier.js";
import {
  PermissionsClient,
  evaluatePermissionEntry,
  type CheckResult,
  type PermissionEntry,
} from "./permissions.js";
import type { Resource } from "./abac.js";
import { Parse } from "./permission.js";
import {
  Authenticate,
  Require,
  UnauthorizedError,
  type MiddlewareRequest,
} from "./middleware.js";
import type { PermissionSubscription } from "./events.js";

export interface ClientOptions {
  readonly remoteOnly?: boolean;
}

export type ClientOption = (client: Client) => void;

export class Client {
  public verifier?: Verifier;
  public permissions?: PermissionsClient;
  public remoteOnly: boolean;

  public constructor(
    verifierOrOptions?: Verifier | ClientOptions & { verifier?: Verifier; permissions?: PermissionsClient } | null,
    permissions?: PermissionsClient | null,
    options?: ClientOptions,
  ) {
    if (isVerifier(verifierOrOptions)) {
      this.verifier = verifierOrOptions;
      this.permissions = permissions ?? undefined;
      this.remoteOnly = options?.remoteOnly ?? false;
      return;
    }
    const configured = verifierOrOptions ?? {};
    this.verifier = configured.verifier;
    this.permissions = configured.permissions;
    this.remoteOnly = configured.remoteOnly ?? options?.remoteOnly ?? false;
  }

  public async authenticate(request: MiddlewareRequest): Promise<Claims> {
    if (this.verifier === undefined) {
      throw new UnauthorizedError("authentication verifier unavailable");
    }
    return Authenticate(request, this.verifier);
  }

  public async Authenticate(request: MiddlewareRequest): Promise<Claims> {
    return this.authenticate(request);
  }

  public async allow(
    claims: Claims,
    permission: string,
    resource?: Resource,
    signal?: AbortSignal,
  ): Promise<{ allow: boolean; reason: string }>;
  public async allow(
    signal: AbortSignal | undefined,
    claims: Claims,
    permission: string,
    resource?: Resource,
  ): Promise<{ allow: boolean; reason: string }>;
  public async allow(...args: unknown[]): Promise<{ allow: boolean; reason: string }> {
    const parsed = parseAllowArguments(args);
    const claims = parsed.claims;
    if (claims.subject.trim() === "") return { allow: false, reason: "subject is missing" };
    if (!claims.expiry || claims.expiry.getTime() <= Date.now()) {
      return { allow: false, reason: "access token is expired" };
    }
    Parse(parsed.permission);
    if (this.remoteOnly || this.permissions === undefined) {
      return this.remoteAllow(parsed.signal, claims.subject, parsed.permission, parsed.resource);
    }
    let entry: PermissionEntry;
    try {
      entry = await this.permissions.get(claims.subject, claims.permVer, parsed.signal);
    } catch {
      return this.remoteAllow(parsed.signal, claims.subject, parsed.permission, parsed.resource);
    }
    if (entry.perm_ver !== claims.permVer) {
      return { allow: false, reason: "permission version mismatch" };
    }
    return evaluatePermissionEntry(entry, claims, parsed.permission, parsed.resource);
  }

  public async Allow(
    claims: Claims,
    permission: string,
    resource?: Resource,
    signal?: AbortSignal,
  ): Promise<{ allow: boolean; reason: string }>;
  public async Allow(
    signal: AbortSignal | undefined,
    claims: Claims,
    permission: string,
    resource?: Resource,
  ): Promise<{ allow: boolean; reason: string }>;
  public async Allow(
    first: Claims | AbortSignal | undefined,
    second: Claims | string,
    third?: string | Resource,
    fourth?: Resource | AbortSignal,
  ): Promise<{ allow: boolean; reason: string }> {
    const invoke = this.allow as unknown as (...values: unknown[]) => Promise<{ allow: boolean; reason: string }>;
    return invoke.call(this, first, second, third, fourth);
  }
  public async check(
    subject: string,
    permission: string,
    resource: Resource = {},
    signal?: AbortSignal,
  ): Promise<CheckResult> {
    if (this.permissions === undefined) {
      throw new Error("permission client is unavailable");
    }
    return this.permissions.check(subject, permission, resource, signal);
  }

  public async Check(
    subject: string,
    permission: string,
    resource?: Resource,
    signal?: AbortSignal,
  ): Promise<CheckResult>;
  public async Check(
    signal: AbortSignal | undefined,
    subject: string,
    permission: string,
    resource?: Resource,
  ): Promise<CheckResult>;
  public async Check(
    first: string | AbortSignal | undefined,
    second: string,
    third?: string | Resource,
    fourth?: Resource | AbortSignal,
  ): Promise<CheckResult> {
    if (typeof first === "string") {
      return this.check(first, second, third as Resource, fourth as AbortSignal | undefined);
    }
    return this.check(second, third as string, fourth as Resource, first);
  }

  public middleware(next?: (request: MiddlewareRequest, claims: Claims) => unknown | Promise<unknown>): (request: MiddlewareRequest) => Promise<Claims | unknown> {
    return async (request: MiddlewareRequest): Promise<Claims | unknown> => {
      const claims = await this.authenticate(request);
      if (next === undefined) return claims;
      return next(request, claims);
    };
  }

  public Middleware(next?: (request: MiddlewareRequest, claims: Claims) => unknown | Promise<unknown>): (request: MiddlewareRequest) => Promise<Claims | unknown> {
    return this.middleware(next);
  }

  public require(
    permission: string,
    resourceFrom?: Resource | ((request: MiddlewareRequest) => Resource | Promise<Resource>),
  ): (request: MiddlewareRequest, claims?: Claims) => Promise<Claims> {
    return Require(this, permission, resourceFrom);
  }

  public Require(
    permission: string,
    resourceFrom?: Resource | ((request: MiddlewareRequest) => Resource | Promise<Resource>),
  ): (request: MiddlewareRequest, claims?: Claims) => Promise<Claims> {
    return this.require(permission, resourceFrom);
  }

  public async subscribePermissions(
    sourceOrURL: unknown,
    handler?: (userIDs: readonly string[]) => void | Promise<void>,
  ): Promise<PermissionSubscription | null> {
    if (this.permissions === undefined) throw new Error("permission client is unavailable");
    return this.permissions.subscribePermissions(sourceOrURL, handler);
  }

  public async SubscribePermissions(
    sourceOrURL: unknown,
    handler?: (userIDs: readonly string[]) => void | Promise<void>,
  ): Promise<PermissionSubscription | null> {
    return this.subscribePermissions(sourceOrURL, handler);
  }

  private async remoteAllow(
    signal: AbortSignal | undefined,
    subject: string,
    permission: string,
    resource: Resource,
  ): Promise<{ allow: boolean; reason: string }> {
    try {
      const result = await this.check(subject, permission, resource, signal);
      return { allow: result.allow, reason: result.reason };
    } catch {
      return { allow: false, reason: "authorization service unavailable" };
    }
  }
}

export function newClient(
  verifier?: Verifier,
  permissions?: PermissionsClient,
  options?: ClientOptions,
): Client {
  return new Client(verifier, permissions, options);
}

export const NewClient = newClient;

export function withVerifier(verifier: Verifier): ClientOption {
  return (client) => {
    client.verifier = verifier;
  };
}

export const WithVerifier = withVerifier;

export function withPermissions(permissions: PermissionsClient): ClientOption {
  return (client) => {
    client.permissions = permissions;
  };
}

export const WithPermissions = withPermissions;
export const WithPermissionsClient = withPermissions;

export function withRemoteOnly(remoteOnly: boolean): ClientOption {
  return (client) => {
    client.remoteOnly = remoteOnly;
  };
}

export const WithRemoteOnly = withRemoteOnly;


function parseAllowArguments(args: readonly unknown[]): {
  claims: Claims;
  permission: string;
  resource: Resource;
  signal?: AbortSignal;
} {
  let offset = 0;
  let signal: AbortSignal | undefined;
  if (isAbortSignal(args[0]) || args[0] === undefined && args.length >= 4) {
    signal = isAbortSignal(args[0]) ? args[0] : undefined;
    offset = 1;
  }
  const claims = args[offset];
  const permission = args[offset + 1];
  const resource = args[offset + 2] ?? {};
  const trailingSignal = args[offset + 3];
  if (!isClaimsLike(claims) || typeof permission !== "string" || !isResourceLike(resource)) {
    throw new TypeError("allow requires claims, permission, and resource");
  }
  if (signal === undefined && isAbortSignal(trailingSignal)) signal = trailingSignal;
  return { claims, permission, resource, signal };
}
function isAbortSignal(value: unknown): value is AbortSignal {
  return typeof value === "object" && value !== null && "aborted" in value && "addEventListener" in value;
}


function isVerifier(value: unknown): value is Verifier {
  return value instanceof Verifier || typeof value === "object" && value !== null && "verify" in value && typeof value.verify === "function";
}

function isClaimsLike(value: unknown): value is Claims {
  return typeof value === "object" && value !== null &&
    "subject" in value && typeof value.subject === "string" &&
    "permVer" in value && typeof value.permVer === "number" &&
    "kind" in value && (value.kind === "user" || value.kind === "service") &&
    "expiry" in value && value.expiry instanceof Date;
}

function isResourceLike(value: unknown): value is Resource {
  return typeof value === "object" && value !== null;
}

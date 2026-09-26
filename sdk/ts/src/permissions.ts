import { CompileCondition, type CompiledCondition, type Context, type Resource } from "./abac.js";
import { Parse, type Permission } from "./permission.js";
import type { Claims } from "./verifier.js";
import { SDKError } from "./verifier.js";
import { subscribePermissions, type PermissionSubscription } from "./events.js";

export const DEFAULT_PERMISSION_TTL_MS = 2 * 60 * 1000;

/** Minimal response contract used by permission fetchers and test stubs. */
export interface PermissionResponse {
  readonly ok: boolean;
  readonly status: number;
  json(): Promise<unknown>;
}

export interface PermissionRequestInit {
  readonly method?: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: string;
  readonly signal?: AbortSignal;
}

export type PermissionFetcher = (
  url: string,
  init?: PermissionRequestInit,
) => Promise<PermissionResponse>;

export interface PermissionsOptions {
  readonly serviceToken?: string;
  readonly token?: string;
  readonly tokenSource?: () => string | Promise<string>;
  readonly ttlMs?: number;
  readonly cacheTtlMs?: number;
  readonly fetch?: PermissionFetcher;
  readonly fetcher?: PermissionFetcher;
  readonly baseURL?: string;
}

/** A grant returned by `/authz/permissions/{userID}`. */
export class Grant {
  public readonly key: string;
  public readonly condition?: CompiledCondition;
  public readonly permission: Permission;

  public constructor(key: string, condition?: CompiledCondition | string | null);
  public constructor(values: { readonly key: string; readonly condition?: CompiledCondition | string | null });
  public constructor(
    keyOrValues: string | { readonly key: string; readonly condition?: CompiledCondition | string | null },
    suppliedCondition?: CompiledCondition | string | null,
  ) {
    const key = typeof keyOrValues === "string" ? keyOrValues : keyOrValues.key;
    const condition = typeof keyOrValues === "string" ? suppliedCondition : keyOrValues.condition;
    this.key = key;
    this.permission = Parse(key);
    if (typeof condition === "string" && condition.trim() !== "") {
      this.condition = CompileCondition(condition);
    } else if (typeof condition === "object" && condition !== null && "eval" in condition) {
      const compiled = condition as CompiledCondition;
      this.condition = compiled;
    }
  }

  public get Key(): string {
    return this.key;
  }

  public get Condition(): CompiledCondition | undefined {
    return this.condition;
  }

  public toJSON(): { key: string; condition?: string } {
    const wire: { key: string; condition?: string } = { key: this.key };
    if (this.condition !== undefined && this.condition.source.trim() !== "") {
      wire.condition = this.condition.source;
    }
    return wire;
  }
}
export type GrantInput = Grant | {
  readonly key: string;
  readonly condition?: CompiledCondition | string | null;
};

export interface PermissionEntry {
  readonly user_id: string;
  readonly perm_ver: number;
  readonly grants: readonly GrantInput[];
  readonly userId?: string;
  readonly permVer?: number;
  readonly Grants?: readonly GrantInput[];
  readonly UserID?: string;
  readonly PermVer?: number;
}

export type Permissions = PermissionEntry;
export type CachedPermissions = PermissionEntry;

export interface CheckResult {
  readonly allow: boolean;
  readonly matched: readonly string[];
  readonly reason: string;
  readonly Allow?: boolean;
  readonly Matched?: readonly string[];
  readonly Reason?: string;
}

/** Errors raised while loading a permission entry. */
export class PermissionFetchError extends SDKError {
  public constructor(message: string, cause?: unknown) {
    super("PERMISSION_FETCH_FAILED", message, cause);
  }
}

export { PermissionFetchError as PermissionsError };

interface CachedPermissionEntry {
  readonly entry: PermissionEntry;
  readonly expiresAt: number;
}

interface InFlightPermission {
  readonly permVer: number;
  readonly promise: Promise<PermissionEntry>;
}

/** Local permission cache plus authoritative `/authz/check` access. */
export class PermissionsClient {
  private readonly base: string;
  private readonly serviceToken?: string;
  private readonly tokenSource?: () => string | Promise<string>;
  private readonly ttlMs: number;
  private readonly fetcher: PermissionFetcher;
  private readonly entries = new Map<string, CachedPermissionEntry>();
  private readonly inFlight = new Map<string, InFlightPermission>();

  public constructor(baseURL: string, options?: PermissionsOptions | string | (() => string | Promise<string>)) {
    const resolvedOptions: PermissionsOptions =
      typeof options === "string" ? { serviceToken: options } :
      typeof options === "function" ? { tokenSource: options } : options ?? {};
    this.base = (resolvedOptions.baseURL ?? baseURL).trim().replace(/\/+$/, "");
    this.serviceToken = (resolvedOptions.serviceToken ?? resolvedOptions.token)?.trim();
    this.tokenSource = resolvedOptions.tokenSource;
    const configuredTTL = resolvedOptions.ttlMs ?? resolvedOptions.cacheTtlMs ?? DEFAULT_PERMISSION_TTL_MS;
    this.ttlMs = Number.isFinite(configuredTTL) && configuredTTL >= 0 ? configuredTTL : DEFAULT_PERMISSION_TTL_MS;
    this.fetcher =
      resolvedOptions.fetcher ??
      resolvedOptions.fetch ??
      (async (url: string, init?: PermissionRequestInit) => globalThis.fetch(url, init));
  }

  /** Return a cached entry or single-flight its user-specific fetch. */
  public async get(userID: string, tokenPermVer: number, signal?: AbortSignal): Promise<PermissionEntry> {
    const normalizedUserID = userID.trim();
    if (normalizedUserID === "") {
      throw new PermissionFetchError("user ID is empty");
    }
    for (;;) {
      const cached = this.entries.get(normalizedUserID);
      if (cached !== undefined && cached.expiresAt > Date.now() && cached.entry.perm_ver === tokenPermVer) {
        return clonePermissionEntry(cached.entry);
      }

      const running = this.inFlight.get(normalizedUserID);
      if (running !== undefined) {
        const result = await waitForSignal(running.promise, signal);
        if (result.perm_ver === tokenPermVer) {
          return clonePermissionEntry(result);
        }
        continue;
      }

      const promise = this.fetchPermissions(normalizedUserID, signal);
      this.inFlight.set(normalizedUserID, { permVer: tokenPermVer, promise });
      try {
        const result = await waitForSignal(promise, signal);
        this.entries.set(normalizedUserID, {
          entry: clonePermissionEntry(result),
          expiresAt: Date.now() + this.ttlMs,
        });
        return clonePermissionEntry(result);
      } finally {
        const current = this.inFlight.get(normalizedUserID);
        if (current?.promise === promise) {
          this.inFlight.delete(normalizedUserID);
        }
      }
    }
  }

  public async Get(userID: string, tokenPermVer: number, signal?: AbortSignal): Promise<PermissionEntry>;
  public async Get(signal: AbortSignal | undefined, userID: string, tokenPermVer: number): Promise<PermissionEntry>;
  public async Get(
    first: string | AbortSignal | undefined,
    second: number | string,
    third?: number | AbortSignal,
  ): Promise<PermissionEntry> {
    if (typeof first === "string") {
      return this.get(first, second as number, third as AbortSignal | undefined);
    }
    return this.get(second as string, third as number, first);
  }

  /** Invalidate one or more user entries. Empty IDs are ignored. */
  public invalidate(...userIDs: string[]): void {
    for (const userID of userIDs) {
      const normalized = userID.trim();
      if (normalized !== "") this.entries.delete(normalized);
    }
  }

  public Invalidate(...userIDs: string[]): void {
    this.invalidate(...userIDs);
  }

  public invalidatePermissions(...userIDs: string[]): void {
    this.invalidate(...userIDs);
  }

  public InvalidatePermissions(...userIDs: string[]): void {
    this.invalidate(...userIDs);
  }

  public invalidateAll(): void {
    this.entries.clear();
  }

  public InvalidateAll(): void {
    this.invalidateAll();
  }

  public clear(): void {
    this.invalidateAll();
  }

  public Clear(): void {
    this.clear();
  }

  /** Perform the authoritative POST `/authz/check` request. */
  public async check(
    subject: string,
    permission: string,
    resource: Resource = {},
    signal?: AbortSignal,
  ): Promise<CheckResult> {
    if (subject.trim() === "") throw new PermissionFetchError("subject is empty");
    Parse(permission);
    const token = await this.serviceBearer();
    const endpoint = `${this.base}/authz/check`;
    const body = JSON.stringify({
      subject,
      permission,
      context: { resource: resourceToWire(resource) },
    });
    let response: PermissionResponse;
    try {
      response = await this.fetcher(endpoint, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body,
        signal,
      });
    } catch (error) {
      throw new PermissionFetchError("remote authorization check", error);
    }
    if (!response.ok) {
      throw new PermissionFetchError(`remote authorization check: HTTP ${response.status}`);
    }
    let payload: unknown;
    try {
      payload = await response.json();
    } catch (error) {
      throw new PermissionFetchError("decode authorization response", error);
    }
    const result = parseCheckResult(payload);
    return result.reason === "" ? {
      ...result,
      reason: result.allow ? "permission granted" : "permission denied",
    } : result;
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
      return this.check(first, second, third as Resource | undefined, fourth as AbortSignal | undefined);
    }
    return this.check(second, third as string, fourth as Resource | undefined, first);
  }

  /** Evaluate a cached entry against identity and resource context. */
  public async allow(
    claims: Claims,
    permission: string,
    resource: Resource = {},
    signal?: AbortSignal,
  ): Promise<{ allow: boolean; reason: string }> {
    const entry = await this.get(claims.subject, claims.permVer, signal);
    if (entry.perm_ver !== claims.permVer) {
      return { allow: false, reason: "permission version mismatch" };
    }
    return evaluatePermissionEntry(entry, claims, permission, resource);
  }

  public async Allow(
    claims: Claims,
    permission: string,
    resource: Resource = {},
    signal?: AbortSignal,
  ): Promise<{ allow: boolean; reason: string }> {
    return this.allow(claims, permission, resource, signal);
  }

  /** Subscribe to optional permission-changing events. */
  public async subscribePermissions(
    sourceOrURL: unknown,
    handler?: (userIDs: readonly string[]) => void | Promise<void>,
  ): Promise<PermissionSubscription | null> {
    return subscribePermissions(this, sourceOrURL, handler);
  }

  public async SubscribePermissions(
    sourceOrURL: unknown,
    handler?: (userIDs: readonly string[]) => void | Promise<void>,
  ): Promise<PermissionSubscription | null> {
    return this.subscribePermissions(sourceOrURL, handler);
  }

  private async fetchPermissions(userID: string, signal?: AbortSignal): Promise<PermissionEntry> {
    if (this.base === "") throw new PermissionFetchError("authorization base URL is empty");
    const token = await this.serviceBearer();
    const endpoint = `${this.base}/authz/permissions/${encodeURIComponent(userID)}`;
    let response: PermissionResponse;
    try {
      response = await this.fetcher(endpoint, {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
        signal,
      });
    } catch (error) {
      throw new PermissionFetchError("fetch permissions", error);
    }
    if (!response.ok) {
      throw new PermissionFetchError(`fetch permissions: HTTP ${response.status}`);
    }
    let payload: unknown;
    try {
      payload = await response.json();
    } catch (error) {
      throw new PermissionFetchError("decode permissions response", error);
    }
    return parsePermissionEntry(payload, userID);
  }

  private async serviceBearer(): Promise<string> {
    if (this.tokenSource !== undefined) {
      let token: string;
      try {
        token = await this.tokenSource();
      } catch (error) {
        throw new PermissionFetchError("get service token", error);
      }
      if (token.trim() === "") throw new PermissionFetchError("service token is empty");
      return token.trim();
    }
    if (this.serviceToken !== undefined && this.serviceToken !== "") {
      return this.serviceToken;
    }
    throw new PermissionFetchError("service token is not configured");
  }
}

export function parsePermissionEntry(payload: unknown, expectedUserID: string): PermissionEntry {
  if (typeof payload !== "object" || payload === null) {
    throw new PermissionFetchError("decode permissions response: object expected");
  }
  if (!("grants" in payload) || !Array.isArray(payload.grants)) {
    throw new PermissionFetchError("decode permissions response: grants must be an array");
  }
  const userID = readString(payload, "user_id") ?? expectedUserID;
  if (userID !== expectedUserID) {
    throw new PermissionFetchError(`permissions response user_id ${JSON.stringify(userID)} does not match ${JSON.stringify(expectedUserID)}`);
  }
  const permVer = readNumber(payload, "perm_ver");
  if (permVer === undefined || !Number.isSafeInteger(permVer) || permVer < 0) {
    throw new PermissionFetchError("decode permissions response: perm_ver must be a non-negative integer");
  }
  const grants: Grant[] = [];
  for (const rawGrant of payload.grants) {
    try {
      const parsed = parseGrant(rawGrant);
      if (parsed !== undefined) grants.push(parsed);
    } catch {
      // The Go cache skips malformed grants so one bad role cannot widen access.
    }
  }
  return { user_id: userID, perm_ver: permVer, grants, userId: userID, permVer, Grants: grants, UserID: userID, PermVer: permVer };
}

function parseGrant(value: unknown): Grant | undefined {
  if (value instanceof Grant) return value;
  if (typeof value !== "object" || value === null || !("key" in value) || typeof value.key !== "string") return undefined;
  let condition: string | null = null;
  if ("condition" in value) {
    if (value.condition !== null && typeof value.condition !== "string") return undefined;
    condition = value.condition;
  }
  return new Grant(value.key, condition);
}

function parseCheckResult(value: unknown): CheckResult {
  if (typeof value !== "object" || value === null) {
    throw new PermissionFetchError("decode authorization response: object expected");
  }
  const allow = readBoolean(value, "allow");
  if (allow === undefined) throw new PermissionFetchError("decode authorization response: allow must be boolean");
  const matched = "matched" in value && Array.isArray(value.matched)
    ? value.matched.filter((item): item is string => typeof item === "string")
    : [];
  const reason = readString(value, "reason") ?? "";
  return { allow, matched, reason, Allow: allow, Matched: matched, Reason: reason };
}

export function evaluatePermissionEntry(
  entry: PermissionEntry,
  claims: Claims,
  permission: string,
  resource: Resource = {},
): { allow: boolean; reason: string } {
  const requested = Parse(permission);
  let conditionRejected = false;
  let allowed = false;
  let denied = false;
  for (const rawGrant of entry.grants) {
    const grant = normalizeGrant(rawGrant);
    const grantMatches = grant.permission.resource === "*" || grant.permission.resource === requested.resource;
    const actionMatches = grant.permission.action === "*" || grant.permission.action === requested.action;
    const scopeMatches = grant.permission.scope === "*" || grant.permission.scope === requested.scope;
    if (!grantMatches || !actionMatches || !scopeMatches) continue;
    if (grant.condition !== undefined) {
      const context: Context = {
        subject: { id: claims.subject, kind: claims.kind },
        resource,
        request: { time: new Date() },
      };
      if (!grant.condition.eval(context)) {
        conditionRejected = true;
        continue;
      }
    }
    if (grant.permission.deny) denied = true;
    else allowed = true;
  }
  if (denied) return { allow: false, reason: "permission denied" };
  if (allowed) return { allow: true, reason: "permission granted" };
  if (conditionRejected) return { allow: false, reason: "condition denied" };
  return { allow: false, reason: "no matching grant" };
}

function resourceToWire(resource: Resource): Record<string, unknown> {
  const wire: Record<string, unknown> = {
    owner_id: resource.owner_id ?? resource.ownerId ?? "",
    team_id: resource.team_id ?? resource.teamId ?? "",
    attrs: resource.attrs ?? {},
  };
  return wire;
}

function normalizeGrant(value: GrantInput): Grant {
  if (value instanceof Grant) return value;
  return new Grant(value.key, value.condition);
}

function clonePermissionEntry(entry: PermissionEntry): PermissionEntry {
  const grants = entry.grants.map((value) => {
    const grant = normalizeGrant(value);
    return new Grant(grant.key, grant.condition);
  });
  return { user_id: entry.user_id, perm_ver: entry.perm_ver, grants, userId: entry.user_id, permVer: entry.perm_ver, Grants: grants, UserID: entry.user_id, PermVer: entry.perm_ver };
}

function readString(value: object, key: string): string | undefined {
  if (!(key in value)) return undefined;
  const candidate = value[key as keyof typeof value];
  return typeof candidate === "string" ? candidate : undefined;
}

function readNumber(value: object, key: string): number | undefined {
  if (!(key in value)) return undefined;
  const candidate = value[key as keyof typeof value];
  return typeof candidate === "number" ? candidate : undefined;
}

function readBoolean(value: object, key: string): boolean | undefined {
  if (!(key in value)) return undefined;
  const candidate = value[key as keyof typeof value];
  return typeof candidate === "boolean" ? candidate : undefined;
}

async function waitForSignal<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return promise;
  if (signal.aborted) throw new DOMException("operation was aborted", "AbortError");
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(new DOMException("operation was aborted", "AbortError"));
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

export function newPermissionsClient(
  baseURL: string,
  options?: PermissionsOptions | string | (() => string | Promise<string>),
): PermissionsClient {
  return new PermissionsClient(baseURL, options);
}

export const NewPermissionsClient = newPermissionsClient;

export function withServiceToken(serviceToken: string): PermissionsOptions {
  return { serviceToken };
}

export const WithServiceToken = withServiceToken;

export function withTokenSource(tokenSource: () => string | Promise<string>): PermissionsOptions {
  return { tokenSource };
}

export const WithTokenSource = withTokenSource;

export function withPermissionsTTL(ttlMs: number): PermissionsOptions {
  return { ttlMs };
}

export const WithPermissionsTTL = withPermissionsTTL;
export const WithTTL = withPermissionsTTL;

export function withPermissionsHTTPClient(fetcher: PermissionFetcher): PermissionsOptions {
  return { fetcher };
}

export const WithPermissionsHTTPClient = withPermissionsHTTPClient;
export const WithHTTPClient = withPermissionsHTTPClient;

export const DEFAULT_PERMISSION_TTL = DEFAULT_PERMISSION_TTL_MS;

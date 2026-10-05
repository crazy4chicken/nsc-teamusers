import { ConditionCompileError, CompileCondition, type CompiledCondition, type Context, type Resource } from "./abac.js";
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
  public readonly conditionSource?: string;
  public readonly conditionCompileError?: ConditionCompileError;
  public readonly permission: Permission;
  public readonly team_id?: string;

  public constructor(key: string, condition?: CompiledCondition | string | null, teamID?: string | null);
  public constructor(values: {
    readonly key: string;
    readonly condition?: CompiledCondition | string | null;
    readonly team_id?: string | null;
  });
  public constructor(
    keyOrValues: string | {
      readonly key: string;
      readonly condition?: CompiledCondition | string | null;
      readonly team_id?: string | null;
    },
    suppliedCondition?: CompiledCondition | string | null,
    suppliedTeamID?: string | null,
  ) {
    const key = typeof keyOrValues === "string" ? keyOrValues : keyOrValues.key;
    const condition = typeof keyOrValues === "string" ? suppliedCondition : keyOrValues.condition;
    const teamID = typeof keyOrValues === "string" ? suppliedTeamID : keyOrValues.team_id;
    this.key = key;
    this.permission = Parse(key);
    if (teamID !== undefined && teamID !== null) {
      if (typeof teamID !== "string" || teamID === "") {
        throw new TypeError("grant team_id must be a nonempty string or null");
      }
      this.team_id = teamID;
    }
    if (typeof condition === "string" && condition.trim() !== "") {
      this.conditionSource = condition;
      try {
        this.condition = CompileCondition(condition);
      } catch (error) {
        if (!(error instanceof ConditionCompileError)) throw error;
        this.conditionCompileError = error;
      }
    } else if (typeof condition === "object" && condition !== null && "eval" in condition) {
      this.condition = condition as CompiledCondition;
      this.conditionSource = (condition as CompiledCondition).source;
    }
  }

  public get Key(): string {
    return this.key;
  }

  public get Condition(): CompiledCondition | undefined {
    return this.condition;
  }

  public toJSON(): { key: string; condition?: string; team_id?: string } {
    const wire: { key: string; condition?: string; team_id?: string } = { key: this.key };
    if (this.conditionSource !== undefined && this.conditionSource.trim() !== "") {
      wire.condition = this.conditionSource;
    }
    if (this.team_id !== undefined) {
      wire.team_id = this.team_id;
    }
    return wire;
  }
}

export type GrantInput = Grant | {
  readonly key: string;
  readonly condition?: CompiledCondition | string | null;
  readonly team_id?: string | null;
};

export interface PermissionEntry {
  readonly user_id: string;
  readonly perm_ver: number;
  readonly grants: readonly GrantInput[];
  readonly valid_until?: string;
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
export class PermissionSnapshotError extends PermissionFetchError {}

export { PermissionFetchError as PermissionsError };

interface CachedPermissionEntry {
  readonly entry: PermissionEntry;
  readonly expiresAt: number;
}

interface InFlightPermission {
  readonly permVer: number;
  readonly clearEpoch: number;
  readonly userEpoch: number;
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
  private clearEpoch = 0;
  private readonly userEpochs = new Map<string, number>();

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

      const existing = this.inFlight.get(normalizedUserID);
      if (existing !== undefined) {
        let result: PermissionEntry;
        try {
          result = await waitForSignal(existing.promise, signal);
        } catch (error) {
          if (this.isInvalidated(normalizedUserID, existing)) {
            throw new PermissionSnapshotError("permission cache invalidated during fetch");
          }
          throw error;
        }
        if (this.isInvalidated(normalizedUserID, existing)) {
          throw new PermissionSnapshotError("permission cache invalidated during fetch");
        }
        if (result.perm_ver === tokenPermVer) {
          if (result.valid_until !== undefined) {
            const deadline = parseRFC3339(result.valid_until);
            if (deadline === undefined || deadline <= Date.now()) {
              throw new PermissionSnapshotError("decode permissions response: valid_until is expired or invalid");
            }
          }
          return clonePermissionEntry(result);
        }
        continue;
      }

      const clearEpoch = this.clearEpoch;
      const userEpoch = this.userEpochs.get(normalizedUserID) ?? 0;
      const promise = this.fetchPermissions(normalizedUserID, signal);
      const newCall: InFlightPermission = {
        permVer: tokenPermVer,
        clearEpoch,
        userEpoch,
        promise,
      };
      this.inFlight.set(normalizedUserID, newCall);
      try {
        let result: PermissionEntry;
        try {
          result = await waitForSignal(promise, signal);
        } catch (error) {
          if (this.isInvalidated(normalizedUserID, newCall)) {
            throw new PermissionSnapshotError("permission cache invalidated during fetch");
          }
          throw error;
        }
        if (this.isInvalidated(normalizedUserID, newCall)) {
          throw new PermissionSnapshotError("permission cache invalidated during fetch");
        }
        const cachedAt = Date.now();
        let expiresAt = cachedAt + this.ttlMs;
        if (result.valid_until !== undefined) {
          const deadline = parseRFC3339(result.valid_until);
          if (deadline === undefined || deadline <= cachedAt) {
            throw new PermissionSnapshotError("decode permissions response: valid_until is expired or invalid");
          }
          expiresAt = Math.min(expiresAt, deadline);
        }
        this.entries.set(normalizedUserID, { entry: clonePermissionEntry(result), expiresAt });
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
      if (normalized !== "") {
        this.userEpochs.set(normalized, (this.userEpochs.get(normalized) ?? 0) + 1);
        this.entries.delete(normalized);
        this.inFlight.delete(normalized);
      }
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
    this.clearEpoch += 1;
    this.userEpochs.clear();
    this.inFlight.clear();
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

  private isInvalidated(userID: string, running: InFlightPermission): boolean {
    return (
      this.clearEpoch !== running.clearEpoch ||
      (this.userEpochs.get(userID) ?? 0) !== running.userEpoch
    );
  }

  private async fetchPermissions(userID: string, signal?: AbortSignal): Promise<PermissionEntry> {
    if (this.base === "") throw new PermissionFetchError("authorization base URL is empty");
    const token = await this.serviceBearer();
    const endpoint = `${this.base}/authz/permissions/${encodeURIComponent(userID)}?version=2`;
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
      if (response.status === 400) {
        throw new PermissionSnapshotError(`fetch permissions: HTTP ${response.status}`);
      }
      throw new PermissionFetchError(`fetch permissions: HTTP ${response.status}`);
    }
    let payload: unknown;
    try {
      payload = await response.json();
    } catch (error) {
      throw new PermissionSnapshotError("decode permissions response", error);
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
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new PermissionSnapshotError("decode permissions response: object expected");
  }
  const fields = payload as Record<string, unknown>;
  if (fields.version !== 2) {
    throw new PermissionSnapshotError("decode permissions response: version must be 2");
  }
  if (typeof fields.user_id !== "string" || fields.user_id.trim() === "") {
    throw new PermissionSnapshotError("decode permissions response: user_id must be a nonempty string");
  }
  const userID = fields.user_id;
  if (userID !== expectedUserID) {
    throw new PermissionSnapshotError(`permissions response user_id ${JSON.stringify(userID)} does not match ${JSON.stringify(expectedUserID)}`);
  }
  if (typeof fields.perm_ver !== "number" || !Number.isSafeInteger(fields.perm_ver) || fields.perm_ver < 0) {
    throw new PermissionSnapshotError("decode permissions response: perm_ver must be a non-negative integer");
  }
  if (!Array.isArray(fields.grants)) {
    throw new PermissionSnapshotError("decode permissions response: grants must be an array");
  }
  let validUntil: string | undefined;
  if (Object.prototype.hasOwnProperty.call(fields, "valid_until")) {
    if (typeof fields.valid_until !== "string") {
      throw new PermissionSnapshotError("decode permissions response: valid_until must be an RFC3339 string");
    }
    const deadline = parseRFC3339(fields.valid_until);
    if (deadline === undefined) {
      throw new PermissionSnapshotError("decode permissions response: valid_until must be an RFC3339 string");
    }
    if (deadline <= Date.now()) {
      throw new PermissionSnapshotError("decode permissions response: valid_until is expired");
    }
    validUntil = fields.valid_until;
  }
  const grants: Grant[] = [];
  for (const [index, rawGrant] of fields.grants.entries()) {
    try {
      grants.push(parseGrant(rawGrant));
    } catch (error) {
      if (error instanceof PermissionSnapshotError) throw error;
      throw new PermissionSnapshotError(`decode permissions response: invalid grant ${index}`, error);
    }
  }
  return {
    user_id: userID,
    perm_ver: fields.perm_ver,
    grants,
    ...(validUntil === undefined ? {} : { valid_until: validUntil }),
    userId: userID,
    permVer: fields.perm_ver,
    Grants: grants,
    UserID: userID,
    PermVer: fields.perm_ver,
  };
}

function parseGrant(value: unknown): Grant {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new PermissionSnapshotError("decode permissions response: grant object expected");
  }
  const fields = value as Record<string, unknown>;
  if (typeof fields.key !== "string" || fields.key.trim() === "") {
    throw new PermissionSnapshotError("decode permissions response: grant key must be a nonempty string");
  }
  let condition: string | undefined;
  if (Object.prototype.hasOwnProperty.call(fields, "condition")) {
    if (typeof fields.condition !== "string" || fields.condition.trim() === "") {
      throw new PermissionSnapshotError("decode permissions response: grant condition must be a nonempty string");
    }
    condition = fields.condition;
  }
  let teamID: string | null | undefined;
  if (Object.prototype.hasOwnProperty.call(fields, "team_id")) {
    if (fields.team_id === null) {
      teamID = null;
    } else if (typeof fields.team_id === "string" && fields.team_id !== "") {
      teamID = fields.team_id;
    } else {
      throw new PermissionSnapshotError("decode permissions response: grant team_id must be a nonempty string or null");
    }
  }
  try {
    return new Grant(fields.key, condition, teamID);
  } catch (error) {
    throw new PermissionSnapshotError("decode permissions response: invalid grant", error);
  }
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
  if (entry.valid_until !== undefined) {
    const deadline = parseRFC3339(entry.valid_until);
    if (deadline === undefined || deadline <= Date.now()) {
      return { allow: false, reason: "permission snapshot expired" };
    }
  }
  const requested = Parse(permission);
  const resourceTeamID = resource.team_id ?? resource.teamId;
  if (requested.scope === "team" && (!resourceTeamID || resourceTeamID.trim() === "")) {
    return { allow: false, reason: "no matching grant" };
  }
  let conditionRejected = false;
  let allowed = false;
  let denied = false;
  for (const rawGrant of entry.grants) {
    const grant = normalizeGrant(rawGrant);
    if (grant.team_id !== undefined && grant.team_id !== resourceTeamID) continue;
    const grantMatches = grant.permission.resource === "*" || grant.permission.resource === requested.resource;
    const actionMatches = grant.permission.action === "*" || grant.permission.action === requested.action;
    const scopeMatches = grant.permission.scope === "*" || grant.permission.scope === requested.scope;
    if (!grantMatches || !actionMatches || !scopeMatches) continue;
    if (grant.conditionCompileError !== undefined) {
      return { allow: false, reason: "condition_error" };
    }
    if (grant.condition !== undefined) {
      const context: Context = {
        subject: { id: claims.subject, kind: claims.kind },
        resource,
        request: { time: new Date() },
      };
      try {
        if (!grant.condition.evalStrict(context)) {
          conditionRejected = true;
          continue;
        }
      } catch {
        return { allow: false, reason: "condition_error" };
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
  return new Grant(value.key, value.condition, value.team_id);
}

function clonePermissionEntry(entry: PermissionEntry): PermissionEntry {
  const grants = entry.grants.map((value) => {
    const grant = normalizeGrant(value);
    return new Grant(grant.key, grant.condition ?? grant.conditionSource, grant.team_id);
  });
  return {
    user_id: entry.user_id,
    perm_ver: entry.perm_ver,
    grants,
    ...(entry.valid_until === undefined ? {} : { valid_until: entry.valid_until }),
    userId: entry.user_id,
    permVer: entry.perm_ver,
    Grants: grants,
    UserID: entry.user_id,
    PermVer: entry.perm_ver,
  };
}

function readString(value: object, key: string): string | undefined {
  if (!(key in value)) return undefined;
  const candidate = value[key as keyof typeof value];
  return typeof candidate === "string" ? candidate : undefined;
}

function readBoolean(value: object, key: string): boolean | undefined {
  if (!(key in value)) return undefined;
  const candidate = value[key as keyof typeof value];
  return typeof candidate === "boolean" ? candidate : undefined;
}

function parseRFC3339(value: string): number | undefined {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-](\d{2}):(\d{2}))$/.exec(value);
  if (match === null) return undefined;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = month === 2 ? (leapYear ? 29 : 28) : month === 4 || month === 6 || month === 9 || month === 11 ? 30 : 31;
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth || hour > 23 || minute > 59 || second > 59) {
    return undefined;
  }
  if (match[7] !== "Z" && (Number(match[8]) > 23 || Number(match[9]) > 59)) return undefined;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : undefined;
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

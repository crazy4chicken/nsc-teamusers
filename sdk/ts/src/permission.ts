/** A resource/action/scope permission key. */
export class Permission {
  public readonly resource: string;
  public readonly action: string;
  public readonly scope: string;
  public readonly deny: boolean;

  public constructor(values: {
    readonly resource: string;
    readonly action: string;
    readonly scope: string;
    readonly deny?: boolean;
  });
  public constructor(resource: string, action: string, scope: string, deny?: boolean);
  public constructor(
    valuesOrResource: { readonly resource: string; readonly action: string; readonly scope: string; readonly deny?: boolean } | string,
    action?: string,
    scope?: string,
    deny = false,
  ) {
    if (typeof valuesOrResource === "string") {
      this.resource = valuesOrResource;
      this.action = action ?? "";
      this.scope = scope ?? "";
      this.deny = deny;
      return;
    }
    this.resource = valuesOrResource.resource;
    this.action = valuesOrResource.action;
    this.scope = valuesOrResource.scope;
    this.deny = valuesOrResource.deny ?? false;
  }

  public get Resource(): string {
    return this.resource;
  }

  public get Action(): string {
    return this.action;
  }

  public get Scope(): string {
    return this.scope;
  }

  public get Deny(): boolean {
    return this.deny;
  }

  public validate(): void {
    validatePermission(this);
  }


  public Validate(): void {
    this.validate();
  }

  public toString(): string {
    return `${this.deny ? "!" : ""}${this.resource}:${this.action}:${this.scope}`;
  }

  public String(): string {
    return this.toString();
  }
}

export function stringifyPermission(permission: PermissionLike): string {
  const value = new Permission({
    resource: permission.resource ?? permission.Resource ?? "",
    action: permission.action ?? permission.Action ?? "",
    scope: permission.scope ?? permission.Scope ?? "",
    deny: permission.deny ?? permission.Deny,
  });
  return value.String();
}

export const StringPermission = stringifyPermission;

/** Parse and validate a permission key, throwing for malformed input. */
export function parse(key: string): Permission {
  if (typeof key !== "string" || key === "") {
    throw new Error("permission key is empty");
  }
  let deny = false;
  let body = key;
  if (body.startsWith("!")) {
    deny = true;
    body = body.slice(1);
  }
  const parts = body.split(":");
  if (parts.length !== 3) {
    throw new Error("permission key must contain resource, action, and scope");
  }
  const permission = new Permission({ resource: parts[0], action: parts[1], scope: parts[2], deny });
  validatePermission(permission);
  return permission;
}

export const Parse = parse;
export const parsePermission = parse;
export const ParsePermission = parse;

/** Validate a permission key object. */
export function validatePermission(permission: PermissionLike): void {
  const resource = permission.resource ?? permission.Resource;
  const action = permission.action ?? permission.Action;
  const scope = permission.scope ?? permission.Scope;
  if (resource === undefined || action === undefined || scope === undefined) {
    throw new Error("permission fields are required");
  }
  validateResource(resource);
  validateAction(action);
  validateScope(scope);
  if (resource === "iam" && scope !== "any") {
    const teamAreas = ["teams", "groups", "roles", "bindings"];
    if (!(scope === "team" && teamAreas.includes(action))) {
      throw new Error(`invalid iam permission scope ${JSON.stringify(scope)} for area ${JSON.stringify(action)}`);
    }
  }
}

export const ValidatePermission = validatePermission;

export type PermissionLike = {
  readonly resource?: string;
  readonly action?: string;
  readonly scope?: string;
  readonly deny?: boolean;
  readonly Resource?: string;
  readonly Action?: string;
  readonly Scope?: string;
  readonly Deny?: boolean;
};

/** Match a grant and request segment-wise, including deny identity. */
export function match(grant: PermissionLike, request: PermissionLike): boolean {
  try {
    validatePermission(grant);
    validatePermission(request);
  } catch {
    return false;
  }
  const grantDeny = grant.deny ?? grant.Deny ?? false;
  const requestDeny = request.deny ?? request.Deny ?? false;
  const grantResource = grant.resource ?? grant.Resource as string;
  const requestResource = request.resource ?? request.Resource as string;
  const grantAction = grant.action ?? grant.Action as string;
  const requestAction = request.action ?? request.Action as string;
  const grantScope = grant.scope ?? grant.Scope as string;
  const requestScope = request.scope ?? request.Scope as string;
  return grantDeny === requestDeny &&
    matchSegment(grantResource, requestResource) &&
    matchSegment(grantAction, requestAction) &&
    matchSegment(grantScope, requestScope);
}

export const Match = match;

/** Parse and match two permission keys. */
export function matchKeys(grant: string, request: string): boolean {
  try {
    return match(parse(grant), parse(request));
  } catch {
    return false;
  }
}

export const MatchKeys = matchKeys;

function validateResource(resource: string): void {
  if (resource === "" || !isLowerAlpha(resource[0])) {
    throw new Error(`invalid permission resource ${JSON.stringify(resource)}`);
  }
  for (let index = 1; index < resource.length; index += 1) {
    const char = resource[index];
    if (!isLowerAlpha(char) && !isDigit(char) && char !== "_" && char !== "." && char !== "-") {
      throw new Error(`invalid permission resource ${JSON.stringify(resource)}`);
    }
  }
}

function validateAction(action: string): void {
  if (action === "*") return;
  if (action === "" || !isLowerAlpha(action[0])) {
    throw new Error(`invalid permission action ${JSON.stringify(action)}`);
  }
  for (let index = 1; index < action.length; index += 1) {
    const char = action[index];
    if (!isLowerAlpha(char) && !isDigit(char) && char !== "_" && char !== "-") {
      throw new Error(`invalid permission action ${JSON.stringify(action)}`);
    }
  }
}

function validateScope(scope: string): void {
  if (scope !== "own" && scope !== "team" && scope !== "any" && scope !== "*") {
    throw new Error(`invalid permission scope ${JSON.stringify(scope)}`);
  }
}

function matchSegment(grant: string, request: string): boolean {
  return grant === "*" || grant === request;
}

function isLowerAlpha(char: string | undefined): boolean {
  return char !== undefined && char >= "a" && char <= "z";
}

function isDigit(char: string | undefined): boolean {
  return char !== undefined && char >= "0" && char <= "9";
}

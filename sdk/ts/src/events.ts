import { SDKError } from "./verifier.js";

export const PERMISSION_EVENT_SUBJECTS = [
  "iam.perm.changed",
  "iam.user.disabled",
  "iam.role.updated",
] as const;

export const PermissionEventSubjects = PERMISSION_EVENT_SUBJECTS;

export interface PermissionEventSource {
  subscribe(
    subject: string,
    handler: (message: unknown) => void | Promise<void>,
  ): unknown;
  close?(): void | Promise<void>;
  drain?(): void | Promise<void>;
}

interface PermissionCache {
  invalidate(...userIDs: string[]): void;
}

/** Raised only when a non-empty NATS subscription is requested without nats installed. */
export class NATSDependencyError extends SDKError {
  public constructor(cause?: unknown) {
    super("NATS_UNAVAILABLE", "NATS support requires the optional `nats` peer dependency", cause);
  }
}

/** Handle returned by SubscribePermissions. */
export class PermissionSubscription {
  private closed = false;
  private readonly closer: () => void | Promise<void>;

  public constructor(closer: () => void | Promise<void>) {
    this.closer = closer;
  }

  public async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.closer();
  }

  public async unsubscribe(): Promise<void> {
    await this.close();
  }

  public async Unsubscribe(): Promise<void> {
    await this.close();
  }

  public async Close(): Promise<void> {
    await this.close();
  }
}

export { NATSDependencyError as NATSUnavailableError };
export { NATSDependencyError as NATSError };

/** Subscribe a permissions cache to NATS or a framework-neutral event source. */
export async function subscribePermissions(
  client: PermissionCache | null | undefined,
  sourceOrURL: unknown,
  handler?: (userIDs: readonly string[]) => void | Promise<void>,
): Promise<PermissionSubscription | null> {
  if (client === null || client === undefined) {
    throw new Error("nil permissions client");
  }
  if (typeof sourceOrURL === "string") {
    if (sourceOrURL.trim() === "") return null;
    const source = await connectNATS(sourceOrURL.trim());
    return subscribeSource(client, source, handler);
  }
  if (sourceOrURL === null || sourceOrURL === undefined) return null;
  if (!isPermissionEventSource(sourceOrURL)) {
    throw new TypeError("permission subscription source must provide subscribe(subject, handler)");
  }
  return subscribeSource(client, sourceOrURL, handler);
}

function subscribeSource(
  client: PermissionCache,
  source: PermissionEventSource,
  handler?: (userIDs: readonly string[]) => void | Promise<void>,
): PermissionSubscription {
  const subscriptions: Array<{ unsubscribe?: () => void | Promise<void> }> = [];
  const onMessage = async (message: unknown): Promise<void> => {
    const userIDs = extractUserIDs(message);
    if (userIDs.length === 0) return;
    client.invalidate(...userIDs);
    if (handler !== undefined) await handler(userIDs);
  };
  for (const subject of PERMISSION_EVENT_SUBJECTS) {
    const result = source.subscribe(subject, onMessage);
    if (isPromiseLike(result)) {
      void Promise.resolve(result).then((resolved) => {
        if (isUnsubscriber(resolved)) subscriptions.push(resolved);
      }).catch(() => undefined);
    } else if (isUnsubscriber(result)) {
      subscriptions.push(result);
    }
  }
  return new PermissionSubscription(async () => {
    let firstError: unknown;
    for (const subscription of subscriptions) {
      try {
        await subscription.unsubscribe?.();
      } catch (error) {
        firstError ??= error;
      }
    }
    try {
      await source.drain?.();
      await source.close?.();
    } catch (error) {
      firstError ??= error;
    }
    if (firstError !== undefined) throw firstError;
  });
}

async function connectNATS(url: string): Promise<PermissionEventSource> {
  let moduleValue: unknown;
  try {
    // The optional peer must not be imported while the core SDK is loaded.
    const load = Function("specifier", "return import(specifier)") as (specifier: string) => Promise<unknown>;
    moduleValue = await load("nats");
  } catch (error) {
    throw new NATSDependencyError(error);
  }
  if (!isObject(moduleValue) || !("connect" in moduleValue) || typeof moduleValue.connect !== "function") {
    throw new NATSDependencyError(new Error("nats.connect is unavailable"));
  }
  let connection: unknown;
  try {
    connection = await moduleValue.connect(url);
  } catch (error) {
    throw new NATSDependencyError(error);
  }
  if (!isNATSConnection(connection)) {
    throw new NATSDependencyError(new Error("nats connection does not provide subscribe"));
  }
  return {
    subscribe(subject, handler) {
      const subscription = connection.subscribe(subject);
      void consumeNATS(subscription, handler);
      return {
        unsubscribe: async () => {
          await subscription.unsubscribe?.();
        },
      };
    },
    drain: () => connection.drain?.(),
    close: () => connection.close?.(),
  };
}

async function consumeNATS(
  subscription: AsyncIterable<unknown>,
  handler: (message: unknown) => void | Promise<void>,
): Promise<void> {
  try {
    for await (const message of subscription) {
      await handler(message);
    }
  } catch {
    // A closed subscription ends its iterator; event delivery is best effort.
  }
}

function extractUserIDs(message: unknown): string[] {
  const payload = decodeMessage(message);
  if (!isObject(payload)) return [];
  const IDs: string[] = [];
  const arrayValue = payload.user_ids;
  if (Array.isArray(arrayValue)) {
    for (const value of arrayValue) {
      if (typeof value === "string" && value.trim() !== "") IDs.push(value.trim());
    }
  }
  if (typeof payload.user_id === "string" && payload.user_id.trim() !== "") {
    IDs.push(payload.user_id.trim());
  }
  return [...new Set(IDs)];
}

function decodeMessage(message: unknown): unknown {
  if (typeof message === "string") {
    try {
      return JSON.parse(message);
    } catch {
      return undefined;
    }
  }
  if (message instanceof Uint8Array) {
    try {
      return JSON.parse(new TextDecoder().decode(message));
    } catch {
      return undefined;
    }
  }
  if (isObject(message) && "data" in message) {
    return decodeMessage(message.data);
  }
  return message;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isPermissionEventSource(value: unknown): value is PermissionEventSource {
  return isObject(value) && "subscribe" in value && typeof value.subscribe === "function";
}

function isUnsubscriber(value: unknown): value is { unsubscribe: () => void | Promise<void> } {
  return isObject(value) && "unsubscribe" in value && typeof value.unsubscribe === "function";
}

function isPromiseLike(value: unknown): value is PromiseLike<unknown> {
  return isObject(value) && "then" in value && typeof value.then === "function";
}

function isNATSConnection(value: unknown): value is {
  subscribe(subject: string): AsyncIterable<unknown> & { unsubscribe?: () => void | Promise<void> };
  drain?(): void | Promise<void>;
  close?(): void | Promise<void>;
} {
  return isObject(value) && "subscribe" in value && typeof value.subscribe === "function";
}

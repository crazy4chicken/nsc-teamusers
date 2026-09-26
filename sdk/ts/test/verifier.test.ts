import { strict as assert } from "node:assert";
import { test } from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import {
  Authenticate,
  Claims,
  CompileCondition,
  ForbiddenError,
  MatchKeys,
  PermissionsClient,
  Require,
  TokenClaimsError,
  TokenVerificationError,
  UnauthorizedError,
  Verifier,
  type JSONWebKeySet,
} from "../src/index.js";

test("verifies an Ed25519 access token and caches the JWKS", async () => {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA");
  const publicJWK = await exportJWK(publicKey);
  publicJWK.kid = "test-key";
  publicJWK.alg = "EdDSA";
  publicJWK.use = "sig";
  const jwks: JSONWebKeySet = { keys: [publicJWK] };
  let fetchCount = 0;

  const verifier = new Verifier("https://issuer.example/", {
    fetcher: async (url) => {
      fetchCount += 1;
      assert.equal(url, "https://issuer.example/.well-known/jwks.json");
      return {
        ok: true,
        status: 200,
        json: async () => jwks,
      };
    },
  });
  const token = await new SignJWT({
    kind: "user",
    team: "platform",
    perm_ver: 2,
  })
    .setProtectedHeader({ alg: "EdDSA", kid: "test-key" })
    .setIssuer("teamusers")
    .setAudience("teamusers")
    .setSubject("sdk-user")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);

  const claims = await verifier.verify(token);
  assert.ok(claims instanceof Claims);
  assert.equal(claims.subject, "sdk-user");
  assert.equal(claims.sub, "sdk-user");
  assert.equal(claims.team, "platform");
  assert.equal(claims.kind, "user");
  assert.equal(claims.permVer, 2);
  assert.equal(claims.perm_ver, 2);
  assert.equal(claims.audience, "teamusers");
  assert.equal(fetchCount, 1);

  const secondClaims = await verifier.verify(token);
  assert.equal(secondClaims.subject, "sdk-user");
  assert.equal(fetchCount, 1);
});

test("supports an expected audience and rejects invalid application claims", async () => {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA");
  const publicJWK = await exportJWK(publicKey);
  publicJWK.kid = "audience-key";
  publicJWK.alg = "EdDSA";
  const jwks: JSONWebKeySet = { keys: [publicJWK] };
  const verifier = new Verifier("https://issuer.example", {
    audience: "api",
    jwks,
  });
  const token = await new SignJWT({ kind: "service", perm_ver: 0 })
    .setProtectedHeader({ alg: "EdDSA", kid: "audience-key" })
    .setIssuer("teamusers")
    .setAudience("wrong")
    .setSubject("svc")
    .setExpirationTime("5m")
    .sign(privateKey);

  await assert.rejects(verifier.verify(token), TokenVerificationError);

  const validToken = await new SignJWT({ kind: "service", perm_ver: 0 })
    .setProtectedHeader({ alg: "EdDSA", kid: "audience-key" })
    .setIssuer("teamusers")
    .setAudience("api")
    .setSubject("svc")
    .setExpirationTime("5m")
    .sign(privateKey);
  const claims = await verifier.verify(validToken);
  assert.equal(claims.kind, "service");
  assert.equal(claims.permVer, 0);

  const missingKind = await new SignJWT({ perm_ver: 0 })
    .setProtectedHeader({ alg: "EdDSA", kid: "audience-key" })
    .setIssuer("teamusers")
    .setAudience("api")
    .setSubject("svc")
    .setExpirationTime("5m")
    .sign(privateKey);
  await assert.rejects(verifier.verify(missingKind), TokenClaimsError);
});

test("rejects an audience array that contains an extra value", async () => {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA");
  const publicJWK = await exportJWK(publicKey);
  publicJWK.kid = "strict-audience-key";
  publicJWK.alg = "EdDSA";
  const verifier = new Verifier("https://issuer.example", {
    audience: "api",
    jwks: { keys: [publicJWK] },
  });
  const token = await new SignJWT({ kind: "user", perm_ver: 1 })
    .setProtectedHeader({ alg: "EdDSA", kid: "strict-audience-key" })
    .setIssuer("teamusers")
    .setAudience(["api", "other"])
    .setSubject("usr_1")
    .setExpirationTime("5m")
    .sign(privateKey);
  await assert.rejects(verifier.verify(token), TokenClaimsError);
});

test("single-flights concurrent JWKS cache misses", async () => {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA");
  const publicJWK = await exportJWK(publicKey);
  publicJWK.kid = "single-flight-key";
  publicJWK.alg = "EdDSA";
  const jwks: JSONWebKeySet = { keys: [publicJWK] };
  let fetchCount = 0;
  const verifier = new Verifier("https://issuer.example", {
    fetcher: async () => {
      fetchCount += 1;
      return { ok: true, status: 200, json: async () => jwks };
    },
  });
  const token = await new SignJWT({ kind: "user", perm_ver: 1 })
    .setProtectedHeader({ alg: "EdDSA", kid: "single-flight-key" })
    .setIssuer("teamusers")
    .setAudience("teamusers")
    .setSubject("usr_1")
    .setExpirationTime("5m")
    .sign(privateKey);
  await Promise.all(Array.from({ length: 20 }, () => verifier.verify(token)));
  assert.equal(fetchCount, 1);
});

test("matches permission grammar and evaluates documented ABAC conditions", () => {
  assert.equal(MatchKeys("orders:*:team", "orders:read:team"), true);
  assert.equal(MatchKeys("orders:*:team", "orders:read:team:extra"), false);
  assert.equal(MatchKeys("!orders:read:team", "orders:read:team"), false);
  assert.equal(MatchKeys("!orders:read:team", "!orders:read:team"), true);
  const condition = CompileCondition(
    'subject.id == "usr_1" && resource.team_id == "team_1" && resource.attrs["tier"] in ["gold", "platinum"]',
  );
  const values = {
    subject: { id: "usr_1", kind: "user" },
    resource: { team_id: "team_1", attrs: { tier: "gold" } },
    request: { time: new Date() },
  };
  assert.equal(condition.Eval(values), true);
  assert.equal(condition.Eval({ ...values, resource: { ...values.resource, attrs: { tier: "free" } } }), false);
  assert.throws(() => CompileCondition("subject.id"));
  assert.throws(() => CompileCondition("x".repeat(4097)));
});

test("permission cache honors TTL, permission versions, and single-flight", async () => {
  let fetchCount = 0;
  const requests: Array<{ url: string; init?: unknown }> = [];
  const permissions = new PermissionsClient("https://iam.example/", {
    serviceToken: "service-token",
    ttlMs: 60_000,
    fetcher: async (url, init) => {
      fetchCount += 1;
      requests.push({ url, init });
      return {
        ok: true,
        status: 200,
        json: async () => ({
          user_id: "usr_1",
          perm_ver: fetchCount,
          grants: [{ key: "orders:read:team" }],
        }),
      };
    },
  });
  const first = await Promise.all(Array.from({ length: 20 }, () => permissions.get("usr_1", 1)));
  assert.equal(fetchCount, 1);
  assert.equal(first[0].perm_ver, 1);
  await permissions.get("usr_1", 1);
  assert.equal(fetchCount, 1);
  await permissions.get("usr_1", 2);
  assert.equal(fetchCount, 2);
  assert.equal(requests[0].url, "https://iam.example/authz/permissions/usr_1");
  const init = requests[0].init as { method: string; headers: Record<string, string> };
  assert.equal(init.method, "GET");
  assert.equal(init.headers.Authorization, "Bearer service-token");
});

test("middleware returns claims and raises typed 401/403 errors", async () => {
  const claims = new Claims({
    subject: "usr_1",
    team: "",
    kind: "user",
    permVer: 1,
    expiry: new Date(Date.now() + 60_000),
    audience: "teamusers",
  });
  const verifier = { verify: async (raw: string) => {
    assert.equal(raw, "token");
    return claims;
  } };
  assert.equal((await Authenticate({ headers: { Authorization: "Bearer token" }, method: "GET" }, verifier)).subject, "usr_1");
  await assert.rejects(Authenticate({ headers: {}, method: "GET" }, verifier), UnauthorizedError);
  const guard = Require({ allow: async () => ({ allow: false, reason: "condition denied" }) }, "orders:read:team");
  await assert.rejects(guard({ headers: {}, method: "GET" }, claims), ForbiddenError);
});

test("event subscription invalidates affected users", async () => {
  let fetchCount = 0;
  const callbacks = new Map<string, (message: unknown) => void | Promise<void>>();
  const permissions = new PermissionsClient("https://iam.example", {
    serviceToken: "svc",
    fetcher: async () => ({
      ok: true,
      status: 200,
      json: async () => ({ user_id: "usr_1", perm_ver: ++fetchCount, grants: [] }),
    }),
  });
  const source = {
    subscribe(subject: string, callback: (message: unknown) => void | Promise<void>) {
      callbacks.set(subject, callback);
      return { unsubscribe() {} };
    },
  };
  const subscription = await permissions.SubscribePermissions(source);
  await permissions.get("usr_1", 1);
  assert.equal(fetchCount, 1);
  await callbacks.get("iam.perm.changed")?.({ data: JSON.stringify({ user_ids: ["usr_1"] }) });
  await permissions.get("usr_1", 2);
  assert.equal(fetchCount, 2);
  await subscription?.close();
});

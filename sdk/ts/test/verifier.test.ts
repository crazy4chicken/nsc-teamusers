import { strict as assert } from "node:assert";
import { test } from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import {
  Authenticate,
  Claims,
  Client,
  CompileCondition,
  evaluatePermissionEntry,
  ForbiddenError,
  KEY_ROTATION_EVENT_SUBJECT,
  MatchKeys,
  PermissionsClient,
  Require,
  RequireFresh,
  requireFresh,
  RejectImpersonated,
  subscribeKeyRotations,
  subscribeUserDeleted,
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
  const authTime = Math.floor(Date.now() / 1000) - 12;
  const stepUpTime = Math.floor(Date.now() / 1000) - 5;
  const token = await new SignJWT({
    kind: "user",
    team: "platform",
    perm_ver: 2,
    auth_time: authTime,
    step_up_time: stepUpTime,
    amr: ["pwd", "otp"],
    act: { sub: "sdk-admin" },
    imp: true,
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
  assert.equal(claims.authTime, authTime);
  assert.equal(claims.auth_time, authTime);
  assert.equal(claims.stepUpTime, stepUpTime);
  assert.equal(claims.step_up_time, stepUpTime);
  assert.deepEqual(claims.amr, ["pwd", "otp"]);
  assert.equal(claims.actor, "sdk-admin");
  assert.equal(claims.impersonated, true);
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
  assert.equal(claims.authTime, 0);
  assert.equal(claims.stepUpTime, 0);
  assert.deepEqual(claims.amr, []);
  assert.equal(claims.actor, undefined);
  assert.equal(claims.impersonated, false);


  const legacyAuthTime = Math.floor(Date.now() / 1000) - 12;
  const authTimeOnlyToken = await new SignJWT({ kind: "service", perm_ver: 0, auth_time: legacyAuthTime })
    .setProtectedHeader({ alg: "EdDSA", kid: "audience-key" })
    .setIssuer("teamusers")
    .setAudience("api")
    .setSubject("svc")
    .setExpirationTime("5m")
    .sign(privateKey);
  const authTimeOnlyClaims = await verifier.verify(authTimeOnlyToken);
  assert.equal(authTimeOnlyClaims.authTime, legacyAuthTime);
  assert.equal(authTimeOnlyClaims.stepUpTime, 0);
  const missingKind = await new SignJWT({ perm_ver: 0 })
    .setProtectedHeader({ alg: "EdDSA", kid: "audience-key" })
    .setIssuer("teamusers")
    .setAudience("api")
    .setSubject("svc")
    .setExpirationTime("5m")
    .sign(privateKey);
  await assert.rejects(verifier.verify(missingKind), TokenClaimsError);
  const invalidAuthTime = await new SignJWT({ kind: "service", perm_ver: 0, auth_time: -1 })
    .setProtectedHeader({ alg: "EdDSA", kid: "audience-key" })
    .setIssuer("teamusers")
    .setAudience("api")
    .setSubject("svc")
    .setExpirationTime("5m")
    .sign(privateKey);
  await assert.rejects(verifier.verify(invalidAuthTime), TokenClaimsError);

  for (const value of [-1, true, "123", 123.5]) {
    const invalidStepUpTime = await new SignJWT({ kind: "service", perm_ver: 0, step_up_time: value })
      .setProtectedHeader({ alg: "EdDSA", kid: "audience-key" })
      .setIssuer("teamusers")
      .setAudience("api")
      .setSubject("svc")
      .setExpirationTime("5m")
      .sign(privateKey);
    await assert.rejects(verifier.verify(invalidStepUpTime), TokenClaimsError);
  }

  const invalidAMR = await new SignJWT({ kind: "service", perm_ver: 0, amr: "pwd" })
    .setProtectedHeader({ alg: "EdDSA", kid: "audience-key" })
    .setIssuer("teamusers")
    .setAudience("api")
    .setSubject("svc")
    .setExpirationTime("5m")
    .sign(privateKey);
  await assert.rejects(verifier.verify(invalidAMR), TokenClaimsError);

  const invalidAct = await new SignJWT({ kind: "service", perm_ver: 0, act: "sdk-admin" })
    .setProtectedHeader({ alg: "EdDSA", kid: "audience-key" })
    .setIssuer("teamusers")
    .setAudience("api")
    .setSubject("svc")
    .setExpirationTime("5m")
    .sign(privateKey);
  await assert.rejects(verifier.verify(invalidAct), TokenClaimsError);
  const invalidImp = await new SignJWT({
    kind: "service",
    perm_ver: 0,
    act: { sub: "sdk-admin" },
    imp: "true",
  })
    .setProtectedHeader({ alg: "EdDSA", kid: "audience-key" })
    .setIssuer("teamusers")
    .setAudience("api")
    .setSubject("svc")
    .setExpirationTime("5m")
    .sign(privateKey);
  await assert.rejects(verifier.verify(invalidImp), TokenClaimsError);
  const impWithoutActor = await new SignJWT({ kind: "service", perm_ver: 0, imp: true })
    .setProtectedHeader({ alg: "EdDSA", kid: "audience-key" })
    .setIssuer("teamusers")
    .setAudience("api")
    .setSubject("svc")
    .setExpirationTime("5m")
    .sign(privateKey);
  await assert.rejects(verifier.verify(impWithoutActor), TokenClaimsError);
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
          version: 2,
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
  assert.equal(requests[0].url, "https://iam.example/authz/permissions/usr_1?version=2");
  const init = requests[0].init as { method: string; headers: Record<string, string> };
  assert.equal(init.method, "GET");
  assert.equal(init.headers.Authorization, "Bearer service-token");
});

test("permission cache invalidation and clear-all fence in-flight snapshots", async () => {
  type Response = { ok: boolean; status: number; json(): Promise<unknown> };
  const claims = new Claims({
    subject: "usr_1",
    team: "",
    kind: "user",
    permVer: 1,
    expiry: new Date(Date.now() + 60_000),
    audience: "teamusers",
  });
  const invalidators = [
    (permissions: PermissionsClient) => permissions.invalidate("usr_1"),
    (permissions: PermissionsClient) => permissions.invalidateAll(),
  ];
  for (const invalidate of invalidators) {
    let releaseResponse!: (response: Response) => void;
    const heldResponse = new Promise<Response>((resolve) => {
      releaseResponse = resolve;
    });
    let markStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      markStarted = resolve;
    });
    let fetchCount = 0;
    let fallbackCount = 0;
    const permissions = new PermissionsClient("https://iam.example", {
      serviceToken: "svc",
      fetcher: async (url) => {
        if (url.includes("/authz/permissions/")) {
          fetchCount += 1;
          if (fetchCount === 1) {
            markStarted();
            return heldResponse;
          }
          return {
            ok: true,
            status: 200,
            json: async () => ({ version: 2, user_id: "usr_1", perm_ver: 1, grants: [] }),
          };
        }
        fallbackCount += 1;
        return {
          ok: true,
          status: 200,
          json: async () => ({ allow: true, matched: ["orders:read:any"], reason: "permission granted" }),
        };
      },
    });
    const client = new Client({ permissions });
    const original = client.allow(claims, "orders:read:any");
    await started;
    const waiter = client.allow(claims, "orders:read:any");
    invalidate(permissions);
    releaseResponse({
      ok: true,
      status: 200,
      json: async () => ({
        version: 2,
        user_id: "usr_1",
        perm_ver: 1,
        grants: [{ key: "orders:read:any" }],
      }),
    });

    assert.deepEqual(await Promise.all([original, waiter]), [
      { allow: false, reason: "invalid permission snapshot" },
      { allow: false, reason: "invalid permission snapshot" },
    ]);
    assert.equal(fetchCount, 1);
    assert.equal(fallbackCount, 0);
    assert.deepEqual((await permissions.get("usr_1", 1)).grants, []);
    assert.equal(fetchCount, 2);
  }
});

test("permission clients reject legacy and malformed snapshots without fallback", async () => {
  const claims = new Claims({
    subject: "usr_1",
    team: "",
    kind: "user",
    permVer: 1,
    expiry: new Date(Date.now() + 60_000),
    audience: "teamusers",
  });
  const payloads: unknown[] = [
    { user_id: "usr_1", perm_ver: 1, grants: [] },
    { version: 1, user_id: "usr_1", perm_ver: 1, grants: [] },
    { version: 3, user_id: "usr_1", perm_ver: 1, grants: [] },
    { version: 2, user_id: "usr_1", perm_ver: 1, grants: [{ key: "orders:read:any", condition: null }] },
    { version: 2, user_id: "usr_1", perm_ver: 1, grants: [], valid_until: "not-rfc3339" },
    { version: 2, user_id: "usr_1", perm_ver: 1, grants: [], valid_until: new Date(Date.now() - 60_000).toISOString() },
    { version: 2, user_id: "usr_1", perm_ver: 1, grants: [] },
  ];
  let snapshotIndex = 0;
  let fallbackCount = 0;
  const requests: string[] = [];
  const permissions = new PermissionsClient("https://iam.example", {
    serviceToken: "svc",
    fetcher: async (url) => {
      requests.push(url);
      if (url.includes("/authz/permissions/")) {
        const currentIndex = snapshotIndex++;
        const payload = payloads[currentIndex];
        const status = currentIndex === payloads.length - 1 ? 400 : 200;
        return { ok: status === 200, status, json: async () => payload };
      }
      fallbackCount += 1;
      return { ok: true, status: 200, json: async () => ({ allow: true, matched: ["orders:read:any"], reason: "permission granted" }) };
    },
  });
  const client = new Client({ permissions });

  for (const _payload of payloads) {
    assert.deepEqual(
      await client.allow(claims, "orders:read:any", { team_id: "team-a" }),
      { allow: false, reason: "invalid permission snapshot" },
    );
  }
  assert.equal(snapshotIndex, payloads.length);
  assert.equal(fallbackCount, 0);
  assert.equal(requests.every((url) => url.endsWith("?version=2")), true);
});

test("v2 snapshots tolerate additive fields and defer condition compile errors", async () => {
  const claims = new Claims({
    subject: "usr_1",
    team: "",
    kind: "user",
    permVer: 1,
    expiry: new Date(Date.now() + 60_000),
    audience: "teamusers",
  });
  const permissions = new PermissionsClient("https://iam.example", {
    serviceToken: "svc",
    fetcher: async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        version: 2,
        user_id: "usr_1",
        perm_ver: 1,
        future_snapshot_field: { revision: 3 },
        grants: [
          {
            key: "!orders:read:any",
            condition: "subject.id",
            team_id: "team-b",
            future_grant_field: "ignored",
          },
          { key: "iam:teams:any", condition: "subject.id" },
          { key: "orders:read:any" },
        ],
      }),
    }),
  });
  const entry = await permissions.get("usr_1", 1);

  assert.deepEqual(evaluatePermissionEntry(entry, claims, "orders:read:any", { team_id: "team-a" }), {
    allow: true,
    reason: "permission granted",
  });
  assert.deepEqual(evaluatePermissionEntry(entry, claims, "orders:read:any", { team_id: "team-b" }), {
    allow: false,
    reason: "condition_error",
  });
  assert.deepEqual(evaluatePermissionEntry(entry, claims, "orders:write:any", { team_id: "team-b" }), {
    allow: false,
    reason: "no matching grant",
  });
});

test("scoped TypeScript grants isolate teams and retain platform semantics", () => {
  const claims = new Claims({
    subject: "usr_1",
    team: "",
    kind: "user",
    permVer: 1,
    expiry: new Date(Date.now() + 60_000),
    audience: "teamusers",
  });
  const scoped = {
    user_id: "usr_1",
    perm_ver: 1,
    grants: [
      { key: "orders:read:any", team_id: "team-a" },
      { key: "!orders:read:any", team_id: "team-b" },
    ],
  };
  assert.equal(evaluatePermissionEntry(scoped, claims, "orders:read:any", { team_id: "team-a" }).allow, true);
  assert.deepEqual(evaluatePermissionEntry(scoped, claims, "orders:read:any", { team_id: "team-b" }), {
    allow: false,
    reason: "permission denied",
  });
  assert.equal(evaluatePermissionEntry(scoped, claims, "orders:read:any", { team_id: "team-c" }).allow, false);
  assert.equal(evaluatePermissionEntry(scoped, claims, "orders:read:any").allow, false);

  const platform = {
    user_id: "usr_1",
    perm_ver: 1,
    grants: [{ key: "orders:read:any" }, { key: "orders:read:team" }],
  };
  assert.equal(evaluatePermissionEntry(platform, claims, "orders:read:any").allow, true);
  assert.equal(evaluatePermissionEntry(platform, claims, "orders:read:team").allow, false);
  assert.equal(evaluatePermissionEntry(platform, claims, "orders:read:team", { team_id: "team-a" }).allow, true);
  assert.deepEqual(evaluatePermissionEntry({ ...scoped, valid_until: new Date(Date.now() - 1).toISOString() }, claims, "orders:read:any", { team_id: "team-a" }), {
    allow: false,
    reason: "permission snapshot expired",
  });
});

test("conditional grants distinguish false conditions from errors in either order", () => {
  const claims = new Claims({
    subject: "usr_1",
    team: "",
    kind: "user",
    permVer: 1,
    expiry: new Date(Date.now() + 60_000),
    audience: "teamusers",
  });
  const falseDeny = { key: "!orders:read:any", condition: 'resource.attrs["eligible"] == true' };
  const allow = { key: "orders:read:any" };
  for (const grants of [[falseDeny, allow], [allow, falseDeny]]) {
    assert.equal(
      evaluatePermissionEntry({ user_id: "usr_1", perm_ver: 1, grants }, claims, "orders:read:any", { attrs: { eligible: false } }).allow,
      true,
    );
  }

  const errorGrant = { key: "orders:read:any", condition: 'resource.attrs["count"] > 0' };
  for (const grants of [[errorGrant, allow], [allow, errorGrant]]) {
    assert.deepEqual(
      evaluatePermissionEntry({ user_id: "usr_1", perm_ver: 1, grants }, claims, "orders:read:any", { attrs: { count: "not-a-number" } }),
      { allow: false, reason: "condition_error" },
    );
  }
});

test("conditional deny substring matching and false conditions preserve allow", () => {
  const claims = new Claims({
    subject: "usr_1",
    team: "",
    kind: "user",
    permVer: 1,
    expiry: new Date(Date.now() + 60_000),
    audience: "teamusers",
  });
  const condition = CompileCondition('subject.id in resource.attrs["blocked"]');
  const deny = { key: "!orders:read:any", condition };
  const allow = { key: "orders:read:any" };

  for (const grants of [[deny, allow], [allow, deny]]) {
    assert.deepEqual(
      evaluatePermissionEntry(
        { user_id: "usr_1", perm_ver: 1, grants },
        claims,
        "orders:read:any",
        { attrs: { blocked: "blocked:usr_1:also" } },
      ),
      { allow: false, reason: "permission denied" },
    );
    assert.deepEqual(
      evaluatePermissionEntry(
        { user_id: "usr_1", perm_ver: 1, grants },
        claims,
        "orders:read:any",
        { attrs: { blocked: "other-user" } },
      ),
      { allow: true, reason: "permission granted" },
    );
  }

  assert.throws(() => condition.evalStrict({
    subject: { id: "usr_1", kind: "user" },
    resource: { attrs: { blocked: 42 } },
    request: { time: new Date() },
  }));
  assert.deepEqual(
    evaluatePermissionEntry(
      { user_id: "usr_1", perm_ver: 1, grants: [deny, allow] },
      claims,
      "orders:read:any",
      { attrs: { blocked: 42 } },
    ),
    { allow: false, reason: "condition_error" },
  );
});

test("permission cache preserves team scope and expires at valid_until", async () => {
  const originalNow = Date.now;
  let now = originalNow();
  Date.now = () => now;
  try {
    let fetchCount = 0;
    const permissions = new PermissionsClient("https://iam.example", {
      serviceToken: "svc",
      ttlMs: 60_000,
      fetcher: async () => {
        fetchCount += 1;
        return {
          ok: true,
          status: 200,
          json: async () => ({
            version: 2,
            user_id: "usr_1",
            perm_ver: 1,
            grants: [{ key: "orders:read:any", team_id: "team-a" }],
            valid_until: new Date(now + 100).toISOString(),
          }),
        };
      },
    });
    const first = await permissions.get("usr_1", 1);
    const cached = await permissions.get("usr_1", 1);
    assert.equal(first.grants[0]?.team_id, "team-a");
    assert.equal(cached.grants[0]?.team_id, "team-a");
    assert.equal(cached.valid_until, first.valid_until);
    assert.equal(fetchCount, 1);

    now += 101;
    const refreshed = await permissions.get("usr_1", 1);
    assert.equal(refreshed.grants[0]?.team_id, "team-a");
    assert.equal(fetchCount, 2);
  } finally {
    Date.now = originalNow;
  }
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

test("RequireFresh accepts recent auth_time or step_up_time and the shared future skew", async () => {
  const now = Math.floor(Date.now() / 1000);
  const claims = new Claims({
    subject: "usr_1",
    team: "",
    kind: "user",
    permVer: 1,
    expiry: new Date(Date.now() + 60_000),
    audience: "teamusers",
    authTime: now,
    amr: ["pwd", "otp"],
  });
  const guard = RequireFresh(60_000);
  const request = { headers: {}, method: "POST" };
  assert.equal(await guard(request, claims), claims);
  await assert.rejects(guard(request), UnauthorizedError);

  const withTimes = (authTime: number, stepUpTime = 0, impersonated = false) => new Claims({
    subject: claims.subject,
    team: claims.team,
    kind: claims.kind,
    permVer: claims.permVer,
    expiry: claims.expiry,
    audience: claims.audience,
    authTime,
    stepUpTime,
    impersonated,
  });
  const freshStepUp = withTimes(0, now);
  assert.equal(await guard(request, freshStepUp), freshStepUp);
  const oldToken = withTimes(0);
  await assert.rejects(
    guard(request, oldToken),
    (error: unknown) => error instanceof ForbiddenError && error.message === "step_up_required",
  );
  const withinAuthSkew = withTimes(now + 30);
  assert.equal(await guard(request, withinAuthSkew), withinAuthSkew);
  const withinStepUpSkew = withTimes(0, now + 30);
  assert.equal(await requireFresh(60_000)(request, withinStepUpSkew), withinStepUpSkew);

  const freshAuthWithExpiredStepUp = withTimes(now, now - 120);
  assert.equal(await guard(request, freshAuthWithExpiredStepUp), freshAuthWithExpiredStepUp);
  for (const [authTime, stepUpTime] of [
    [now - 120, 0],
    [now + 31, 0],
    [0, now - 120],
    [0, now + 31],
  ]) {
    await assert.rejects(
      guard(request, withTimes(authTime, stepUpTime)),
      (error: unknown) => error instanceof ForbiddenError && error.message === "step_up_required",
    );
  }
  await assert.rejects(
    guard(request, withTimes(0, now, true)),
    (error: unknown) => error instanceof ForbiddenError && error.message === "step_up_required",
  );
  const actorOnlyStepUp = new Claims({
    subject: claims.subject,
    team: claims.team,
    kind: claims.kind,
    permVer: claims.permVer,
    expiry: claims.expiry,
    audience: claims.audience,
    authTime: 0,
    stepUpTime: now,
    actor: "admin_1",
  });
  await assert.rejects(
    guard(request, actorOnlyStepUp),
    (error: unknown) => error instanceof ForbiddenError && error.message === "step_up_required",
  );
  await assert.rejects(
    RequireFresh(0)(request, claims),
    (error: unknown) => error instanceof ForbiddenError && error.message === "step_up_required",
  );
});

test("RejectImpersonated rejects only impersonated claims", async () => {
  const request = { headers: {}, method: "GET" };
  const guard = RejectImpersonated();
  const claims = new Claims({
    subject: "usr_1",
    team: "",
    kind: "user",
    permVer: 1,
    expiry: new Date(Date.now() + 60_000),
    audience: "teamusers",
  });
  assert.equal(await guard(request, claims), claims);
  await assert.rejects(guard(request), UnauthorizedError);

  const impersonated = new Claims({
    subject: "usr_1",
    team: "",
    kind: "user",
    permVer: 1,
    expiry: new Date(Date.now() + 60_000),
    audience: "teamusers",
    actor: "admin_1",
    impersonated: true,
  });
  await assert.rejects(
    guard(request, impersonated),
    (error: unknown) => error instanceof ForbiddenError && error.message === "impersonation_forbidden",
  );
});

test("event subscription invalidates affected users", async () => {
  let fetchCount = 0;
  const callbacks = new Map<string, (message: unknown) => void | Promise<void>>();
  const permissions = new PermissionsClient("https://iam.example", {
    serviceToken: "svc",
    fetcher: async () => ({
      ok: true,
      status: 200,
      json: async () => ({ version: 2, user_id: "usr_1", perm_ver: ++fetchCount, grants: [] }),
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

test("user.deleted lifecycle events do not require changed_fields", async () => {
  const callbacks = new Map<string, (message: unknown) => void | Promise<void>>();
  const source = {
    subscribe(subject: string, callback: (message: unknown) => void | Promise<void>) {
      callbacks.set(subject, callback);
      return { unsubscribe() {} };
    },
  };
  let received: unknown;
  const subscription = await subscribeUserDeleted(source, (event) => {
    received = event;
  });
  await callbacks.get("iam.user.deleted")?.({
    data: JSON.stringify({ event_id: 23, type: "user.deleted", user_id: "usr_1", at: "2026-09-30T00:00:00Z" }),
  });
  assert.deepEqual(received, {
    event_id: 23,
    type: "user.deleted",
    user_id: "usr_1",
    at: "2026-09-30T00:00:00Z",
  });
  await subscription?.close();
});

test("key rotation events refresh the verifier JWKS cache", async () => {
  const { privateKey: previousPrivate, publicKey: previousPublic } = await generateKeyPair("EdDSA");
  const previousJWK = await exportJWK(previousPublic);
  previousJWK.kid = "rotation-previous";
  previousJWK.alg = "EdDSA";
  previousJWK.use = "sig";
  const { privateKey: nextPrivate, publicKey: nextPublic } = await generateKeyPair("EdDSA");
  const nextJWK = await exportJWK(nextPublic);
  nextJWK.kid = "rotation-next";
  nextJWK.alg = "EdDSA";
  nextJWK.use = "sig";

  let jwks: JSONWebKeySet = { keys: [previousJWK] };
  let fetchCount = 0;
  const verifier = new Verifier("https://issuer.example/", {
    fetcher: async () => {
      fetchCount += 1;
      return { ok: true, status: 200, json: async () => jwks };
    },
  });
  const tokenFor = (privateKey: typeof previousPrivate, kid: string) =>
    new SignJWT({ kind: "user", team: "platform", perm_ver: 1 })
      .setProtectedHeader({ alg: "EdDSA", kid })
      .setIssuer("teamusers")
      .setAudience("teamusers")
      .setSubject("sdk-user")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);
  await verifier.verify(await tokenFor(previousPrivate, "rotation-previous"));
  assert.equal(fetchCount, 1);

  const callbacks = new Map<string, (message: unknown) => void | Promise<void>>();
  const source = {
    subscribe(subject: string, callback: (message: unknown) => void | Promise<void>) {
      callbacks.set(subject, callback);
      return { unsubscribe() {} };
    },
  };
  const subscription = await subscribeKeyRotations(verifier, source);
  jwks = { keys: [previousJWK, nextJWK] };
  await callbacks.get(KEY_ROTATION_EVENT_SUBJECT)?.({});

  assert.equal(fetchCount, 2);
  const claims = await verifier.verify(await tokenFor(nextPrivate, "rotation-next"));
  assert.equal(claims.subject, "sdk-user");
  assert.equal(fetchCount, 2);
  await subscription?.close();
});

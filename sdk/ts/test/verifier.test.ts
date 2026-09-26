import { strict as assert } from "node:assert";
import { test } from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import {
  Claims,
  TokenClaimsError,
  TokenVerificationError,
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

import assert from "node:assert/strict";
import crypto from "crypto";
import test from "node:test";
import {
  encryptTokenHandoff,
  openOAuthState,
  parseOAuthStartRequest,
  sealOAuthState,
  type EncryptedOAuthResultPayload,
} from "../lib/withings/oauthHandoff";
import type { TokenBundle } from "../lib/withings/tokenTypes";

const stateSecret = Buffer.from("server-state-secret".repeat(3)).toString(
  "base64url"
);
const walletAddress = "0x1234567890123456789012345678901234567890";
const profileId = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";
const tokenBundle: TokenBundle = {
  access_token: "access-token",
  refresh_token: "refresh-token",
  expires_at: Date.now() + 60_000,
  scope: "user.metrics,user.activity,user.sleepevents",
};

test("sealed OAuth state round-trips and rejects expiry/tampering/wrong secret", () => {
  process.env.WITHINGS_OAUTH_STATE_SECRET = stateSecret;
  const client = createClientHandoff();
  const state = sealOAuthState({
    address: walletAddress,
    profileId,
    callbackNonce: client.callbackNonce,
    callbackPublicKey: client.callbackPublicKey,
    now: 1000,
    ttlSeconds: 1,
  });

  const opened = openOAuthState(state, 1500);
  assert.equal(opened.address, walletAddress.toLowerCase());
  assert.equal(opened.profileId, profileId.toLowerCase());
  assert.equal(opened.callbackNonce, client.callbackNonce);
  assert.equal(opened.callbackPublicKey, client.callbackPublicKey);

  assert.throws(() => openOAuthState(state, 2001), /expired_state/);
  assert.throws(() => openOAuthState(`${state.slice(0, -1)}x`, 1500), /invalid_state/);

  process.env.WITHINGS_OAUTH_STATE_SECRET = Buffer.from(
    "different-state-secret".repeat(3)
  ).toString("base64url");
  assert.throws(() => openOAuthState(state, 1500), /invalid_state/);
});

test("token handoff encrypts the token bundle to the client public key", () => {
  process.env.WITHINGS_OAUTH_STATE_SECRET = stateSecret;
  const client = createClientHandoff();
  const state = openOAuthState(
    sealOAuthState({
      address: walletAddress,
      profileId,
      callbackNonce: client.callbackNonce,
      callbackPublicKey: client.callbackPublicKey,
      now: 1000,
      ttlSeconds: 60,
    }),
    1500
  );

  const encrypted = encryptTokenHandoff({
    state,
    tokenBundle,
    now: 2000,
    ttlSeconds: 60,
  });
  assert.equal(encrypted.includes("access-token"), false);

  const plaintext = decryptTokenHandoff(encrypted, client.ecdh);
  assert.equal(plaintext.walletAddress, walletAddress.toLowerCase());
  assert.equal(plaintext.profileId, profileId.toLowerCase());
  assert.equal(plaintext.callbackNonce, client.callbackNonce);
  assert.deepEqual(plaintext.tokenBundle, tokenBundle);
});

test("OAuth start body validation requires schema, nonce, and P-256 key", () => {
  const client = createClientHandoff();
  assert.deepEqual(
    parseOAuthStartRequest({
      schema: "medoxie.withings.oauth-start.v1",
      callbackNonce: client.callbackNonce,
      callbackPublicKey: client.callbackPublicKey,
    }),
    {
      schema: "medoxie.withings.oauth-start.v1",
      callbackNonce: client.callbackNonce,
      callbackPublicKey: client.callbackPublicKey,
    }
  );
  assert.equal(parseOAuthStartRequest(null), null);
  assert.equal(
    parseOAuthStartRequest({
      schema: "medoxie.withings.oauth-start.v1",
      callbackNonce: "bad",
      callbackPublicKey: client.callbackPublicKey,
    }),
    null
  );
});

function createClientHandoff(): {
  ecdh: crypto.ECDH;
  callbackNonce: string;
  callbackPublicKey: string;
} {
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.generateKeys();
  return {
    ecdh,
    callbackNonce: crypto.randomBytes(24).toString("base64url"),
    callbackPublicKey: ecdh.getPublicKey().toString("base64url"),
  };
}

function decryptTokenHandoff(
  encryptedPayload: string,
  clientEcdh: crypto.ECDH
): Record<string, unknown> & { tokenBundle: TokenBundle } {
  const payload = JSON.parse(
    Buffer.from(encryptedPayload, "base64url").toString("utf8")
  ) as EncryptedOAuthResultPayload;
  const sharedSecret = clientEcdh.computeSecret(
    Buffer.from(payload.serverPublicKey, "base64url")
  );
  const aadBase = {
    schema: payload.schema,
    alg: payload.alg,
    callbackNonce: payload.callbackNonce,
    walletAddress: payload.walletAddress,
    profileId: payload.profileId,
    issuedAt: payload.issuedAt,
    expiresAt: payload.expiresAt,
    serverPublicKey: payload.serverPublicKey,
    salt: payload.salt,
    iv: payload.iv,
  };
  const key = Buffer.from(
    crypto.hkdfSync(
      "sha256",
      sharedSecret,
      Buffer.from(payload.salt, "base64url"),
      Buffer.from(
        [
          "medoxie:withings-oauth-result:v1",
          payload.walletAddress.toLowerCase(),
          payload.profileId.toLowerCase(),
          payload.callbackNonce,
        ].join(":"),
        "utf8"
      ),
      32
    )
  );
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(payload.iv, "base64url")
  );
  decipher.setAAD(Buffer.from(JSON.stringify(aadBase), "utf8"));
  decipher.setAuthTag(Buffer.from(payload.tag, "base64url"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, "base64url")),
    decipher.final(),
  ]).toString("utf8");
  return JSON.parse(plaintext) as Record<string, unknown> & {
    tokenBundle: TokenBundle;
  };
}

import crypto from "crypto";
import type { TokenBundle } from "./tokenTypes";

const OAUTH_START_SCHEMA = "medoxie.withings.oauth-start.v1";
const OAUTH_STATE_SCHEMA = "medoxie.withings.oauth-state.v1";
const OAUTH_RESULT_SCHEMA = "medoxie.withings.oauth-result.v1";
const TOKEN_BUNDLE_SCHEMA = "medoxie.withings.token-bundle.v1";
const HANDOFF_ALG = "ECDH-P256-HKDF-SHA256-AES-GCM";
const STATE_TTL_SECONDS = 10 * 60;
const RESULT_TTL_SECONDS = 10 * 60;

export type OAuthStartRequest = {
  schema: typeof OAUTH_START_SCHEMA;
  callbackNonce: string;
  callbackPublicKey: string;
};

export type OAuthStatePayload = Omit<OAuthStartRequest, "schema"> & {
  schema: typeof OAUTH_STATE_SCHEMA;
  address: string;
  profileId: string;
  issuedAt: number;
  expiresAt: number;
};

export type EncryptedOAuthResultPayload = {
  schema: typeof OAUTH_RESULT_SCHEMA;
  alg: typeof HANDOFF_ALG;
  callbackNonce: string;
  walletAddress: string;
  profileId: string;
  issuedAt: number;
  expiresAt: number;
  serverPublicKey: string;
  salt: string;
  iv: string;
  ciphertext: string;
  tag: string;
};

export function parseOAuthStartRequest(
  body: Record<string, unknown> | null
): OAuthStartRequest | null {
  if (!body || body.schema !== OAUTH_START_SCHEMA) {
    return null;
  }
  const callbackNonce =
    typeof body.callbackNonce === "string" ? body.callbackNonce.trim() : "";
  const callbackPublicKey =
    typeof body.callbackPublicKey === "string"
      ? body.callbackPublicKey.trim()
      : "";
  if (!isValidNonce(callbackNonce) || !isValidP256PublicKey(callbackPublicKey)) {
    return null;
  }
  return {
    schema: OAUTH_START_SCHEMA,
    callbackNonce,
    callbackPublicKey,
  };
}

export function assertOAuthHandoffConfigured(): void {
  getStateKey();
}

export function sealOAuthState(params: {
  address: string;
  profileId: string;
  callbackNonce: string;
  callbackPublicKey: string;
  now?: number;
  ttlSeconds?: number;
}): string {
  const now = params.now ?? Date.now();
  const payload: OAuthStatePayload = {
    schema: OAUTH_STATE_SCHEMA,
    address: params.address.toLowerCase(),
    profileId: params.profileId.toLowerCase(),
    callbackNonce: params.callbackNonce,
    callbackPublicKey: params.callbackPublicKey,
    issuedAt: now,
    expiresAt: now + (params.ttlSeconds ?? STATE_TTL_SECONDS) * 1000,
  };
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", getStateKey(), iv);
  cipher.setAAD(Buffer.from(OAUTH_STATE_SCHEMA, "utf8"));
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(payload), "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return ["v1", toBase64Url(iv), toBase64Url(tag), toBase64Url(ciphertext)].join(
    "."
  );
}

export function openOAuthState(state: string, now = Date.now()): OAuthStatePayload {
  const parts = state.split(".");
  if (parts.length !== 4 || parts[0] !== "v1") {
    throw new Error("invalid_state");
  }
  try {
    const [, ivValue, tagValue, ciphertextValue] = parts;
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      getStateKey(),
      fromBase64Url(ivValue)
    );
    decipher.setAAD(Buffer.from(OAUTH_STATE_SCHEMA, "utf8"));
    decipher.setAuthTag(fromBase64Url(tagValue));
    const plaintext = Buffer.concat([
      decipher.update(fromBase64Url(ciphertextValue)),
      decipher.final(),
    ]).toString("utf8");
    const payload = JSON.parse(plaintext) as OAuthStatePayload;
    if (!isValidOAuthStatePayload(payload)) {
      throw new Error("invalid_state");
    }
    if (payload.expiresAt <= now) {
      throw new Error("expired_state");
    }
    return payload;
  } catch (error) {
    if (error instanceof Error && error.message === "expired_state") {
      throw error;
    }
    throw new Error("invalid_state");
  }
}

export function encryptTokenHandoff(params: {
  state: OAuthStatePayload;
  tokenBundle: TokenBundle;
  now?: number;
  ttlSeconds?: number;
}): string {
  const now = params.now ?? Date.now();
  const serverEcdh = crypto.createECDH("prime256v1");
  serverEcdh.generateKeys();
  const clientPublicKey = fromBase64Url(params.state.callbackPublicKey);
  const sharedSecret = serverEcdh.computeSecret(clientPublicKey);
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const payloadBase: Omit<
    EncryptedOAuthResultPayload,
    "ciphertext" | "tag"
  > = {
    schema: OAUTH_RESULT_SCHEMA,
    alg: HANDOFF_ALG,
    callbackNonce: params.state.callbackNonce,
    walletAddress: params.state.address.toLowerCase(),
    profileId: params.state.profileId.toLowerCase(),
    issuedAt: now,
    expiresAt: now + (params.ttlSeconds ?? RESULT_TTL_SECONDS) * 1000,
    serverPublicKey: toBase64Url(serverEcdh.getPublicKey()),
    salt: toBase64Url(salt),
    iv: toBase64Url(iv),
  };
  const plaintext = {
    schema: TOKEN_BUNDLE_SCHEMA,
    callbackNonce: payloadBase.callbackNonce,
    walletAddress: payloadBase.walletAddress,
    profileId: payloadBase.profileId,
    issuedAt: payloadBase.issuedAt,
    expiresAt: payloadBase.expiresAt,
    tokenBundle: params.tokenBundle,
  };
  const key = deriveHandoffKey({
    sharedSecret,
    salt,
    callbackNonce: payloadBase.callbackNonce,
    walletAddress: payloadBase.walletAddress,
    profileId: payloadBase.profileId,
  });
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(JSON.stringify(payloadBase), "utf8"));
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(plaintext), "utf8"),
    cipher.final(),
  ]);
  const result: EncryptedOAuthResultPayload = {
    ...payloadBase,
    ciphertext: toBase64Url(ciphertext),
    tag: toBase64Url(cipher.getAuthTag()),
  };
  return toBase64Url(Buffer.from(JSON.stringify(result), "utf8"));
}

function isValidOAuthStatePayload(value: OAuthStatePayload): boolean {
  return (
    value?.schema === OAUTH_STATE_SCHEMA &&
    typeof value.address === "string" &&
    value.address.length > 0 &&
    typeof value.profileId === "string" &&
    value.profileId.length > 0 &&
    isValidNonce(value.callbackNonce) &&
    isValidP256PublicKey(value.callbackPublicKey) &&
    Number.isFinite(value.issuedAt) &&
    Number.isFinite(value.expiresAt) &&
    value.expiresAt > value.issuedAt
  );
}

function isValidNonce(value: string): boolean {
  try {
    const bytes = fromBase64Url(value);
    return bytes.length >= 16 && bytes.length <= 64;
  } catch {
    return false;
  }
}

function isValidP256PublicKey(value: string): boolean {
  try {
    const bytes = fromBase64Url(value);
    return bytes.length === 65 && bytes[0] === 0x04;
  } catch {
    return false;
  }
}

function deriveHandoffKey(params: {
  sharedSecret: Buffer;
  salt: Buffer;
  callbackNonce: string;
  walletAddress: string;
  profileId: string;
}): Buffer {
  const info = Buffer.from(
    [
      "medoxie:withings-oauth-result:v1",
      params.walletAddress.toLowerCase(),
      params.profileId.toLowerCase(),
      params.callbackNonce,
    ].join(":"),
    "utf8"
  );
  return Buffer.from(
    crypto.hkdfSync("sha256", params.sharedSecret, params.salt, info, 32)
  );
}

function getStateKey(): Buffer {
  const rawSecret = process.env.WITHINGS_OAUTH_STATE_SECRET?.trim();
  if (!rawSecret) {
    throw new Error("WITHINGS_OAUTH_STATE_SECRET is required");
  }
  const secret = decodeSecret(rawSecret);
  if (secret.length < 32) {
    throw new Error("WITHINGS_OAUTH_STATE_SECRET must be at least 32 bytes");
  }
  return crypto.createHash("sha256").update(secret).digest();
}

function decodeSecret(value: string): Buffer {
  if (/^[0-9a-fA-F]+$/.test(value) && value.length % 2 === 0) {
    return Buffer.from(value, "hex");
  }
  try {
    const decoded = fromBase64Url(value);
    if (decoded.length >= 32) {
      return decoded;
    }
  } catch {
    // Fall through to UTF-8 below.
  }
  return Buffer.from(value, "utf8");
}

function toBase64Url(value: Buffer): string {
  return base64ToBase64Url(value.toString("base64"));
}

function fromBase64Url(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("invalid_base64url");
  }
  return Buffer.from(base64UrlToBase64(value), "base64");
}

function base64ToBase64Url(value: string): string {
  return value.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBase64(value: string): string {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  return base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
}

import assert from "node:assert/strict";
import crypto from "crypto";
import test from "node:test";
import { privateKeyToAccount } from "viem/accounts";
import authCallbackHandler from "../api/withings/auth/callback";
import authResultHandler from "../api/withings/auth/result";
import authStartHandler from "../api/withings/auth/start";
import measureHandler from "../api/withings/measure";
import { openOAuthState } from "../lib/withings/oauthHandoff";

const privateKey =
  "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const account = privateKeyToAccount(privateKey);
const profileId = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";

test("auth/result is retained as a clear 410 compatibility endpoint", async () => {
  const res = createResponse();
  await authResultHandler({ method: "POST", headers: {}, body: {} } as never, res as never);

  assert.equal(res.statusCode, 410);
  assert.equal(res.body.error, "oauth_result_removed");
});

test("auth/callback allows Withings dashboard reachability probes", async () => {
  for (const method of ["GET", "HEAD", "POST", "OPTIONS"]) {
    const res = createResponse();
    await authCallbackHandler(
      { method, headers: {}, query: {} } as never,
      res as never
    );

    assert.equal(res.statusCode, 200, method);
    if (method !== "HEAD" && method !== "OPTIONS") {
      assert.equal(res.body.ok, true);
      assert.equal(res.body.endpoint, "withings_oauth_callback");
    }
  }
});

test("auth/callback still rejects non-GET OAuth callback attempts", async () => {
  const res = createResponse();
  await authCallbackHandler(
    {
      method: "POST",
      headers: {},
      query: { state: "sealed-state", code: "oauth-code" },
    } as never,
    res as never
  );

  assert.equal(res.statusCode, 405);
  assert.equal(res.body.error, "method_not_allowed");
});

test("auth/start accepts encrypted callback metadata and returns a sealed state URL", async () => {
  process.env.WITHINGS_OAUTH_STATE_SECRET = Buffer.from(
    "server-state-secret".repeat(3)
  ).toString("base64url");
  process.env.WITHINGS_CLIENT_ID = "client-id";
  process.env.WITHINGS_REDIRECT_URI = "http://localhost/api/withings/auth/callback";

  const client = createClientHandoff();
  const headers = await signedHeaders("/auth/start");
  const res = createResponse();
  await authStartHandler(
    {
      method: "POST",
      headers,
      url: "/api/withings/auth/start",
      body: {
        schema: "medoxie.withings.oauth-start.v1",
        callbackNonce: client.callbackNonce,
        callbackPublicKey: client.callbackPublicKey,
      },
    } as never,
    res as never
  );

  assert.equal(res.statusCode, 200);
  const authUrl = new URL(res.body.url);
  assert.equal(authUrl.searchParams.get("client_id"), "client-id");
  const state = authUrl.searchParams.get("state");
  assert.ok(state);
  const opened = openOAuthState(state);
  assert.equal(opened.address, account.address.toLowerCase());
  assert.equal(opened.profileId, profileId.toLowerCase());
  assert.equal(opened.callbackNonce, client.callbackNonce);
});

test("data endpoints require a client-supplied token bundle without generating OAuth URLs", async () => {
  const res = createResponse();
  await measureHandler(
    {
      method: "POST",
      headers: await signedHeaders("/measure"),
      query: {},
      body: {
        startdate: "100",
        enddate: "200",
      },
    } as never,
    res as never
  );

  assert.equal(res.statusCode, 401);
  assert.equal(res.body.error, "oauth_required");
  assert.equal("url" in res.body, false);
});

async function signedHeaders(path: string): Promise<Record<string, string>> {
  const timestamp = String(Date.now());
  const message = [
    "Medoxie Withings API Access",
    `address: ${account.address}`,
    `profileId: ${profileId}`,
    `timestamp: ${timestamp}`,
    `path: ${path}`,
  ].join("\n");
  const signature = await account.signMessage({ message });
  return {
    "x-medoxie-address": account.address,
    "x-medoxie-profile-id": profileId,
    "x-medoxie-timestamp": timestamp,
    "x-medoxie-message": Buffer.from(message, "utf8").toString("base64"),
    "x-medoxie-signature": signature,
  };
}

function createClientHandoff(): {
  callbackNonce: string;
  callbackPublicKey: string;
} {
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.generateKeys();
  return {
    callbackNonce: crypto.randomBytes(24).toString("base64url"),
    callbackPublicKey: ecdh.getPublicKey().toString("base64url"),
  };
}

function createResponse(): {
  statusCode: number;
  body: Record<string, any>;
  headers: Record<string, string>;
  status: (code: number) => any;
  json: (payload: Record<string, any>) => any;
  setHeader: (name: string, value: string) => any;
  end: () => void;
} {
  return {
    statusCode: 200,
    body: {},
    headers: {},
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: Record<string, any>) {
      this.body = payload;
      return this;
    },
    setHeader(name: string, value: string) {
      this.headers[name] = value;
      return this;
    },
    end() {
      return undefined;
    },
  };
}

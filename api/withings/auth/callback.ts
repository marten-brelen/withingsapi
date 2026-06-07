import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  enforceHttps,
  sendError,
  sendJson,
} from "../../../lib/withings/http";
import { exchangeCodeForTokens } from "../../../lib/withings/oauth";
import {
  encryptTokenHandoff,
  openOAuthState,
} from "../../../lib/withings/oauthHandoff";

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
): Promise<void> {
  if (!enforceHttps(req, res)) return;

  const state = typeof req.query.state === "string" ? req.query.state : null;
  const code = typeof req.query.code === "string" ? req.query.code : null;

  if (req.method === "HEAD") {
    res.status(200).end();
    return;
  }

  if (req.method === "OPTIONS") {
    res
      .status(200)
      .setHeader("Allow", "GET, HEAD, OPTIONS, POST")
      .end();
    return;
  }

  if (req.method !== "GET") {
    if (!state && !code) {
      sendJson(res, 200, {
        ok: true,
        endpoint: "withings_oauth_callback",
      });
      return;
    }
    sendError(res, 405, "method_not_allowed", "Use GET for OAuth callbacks");
    return;
  }

  if (!state || !code) {
    if (!state && !code) {
      sendJson(res, 200, {
        ok: true,
        endpoint: "withings_oauth_callback",
      });
      return;
    }
    sendError(res, 400, "invalid_request", "state and code are required");
    return;
  }

  let owner;
  try {
    owner = openOAuthState(state);
  } catch (error) {
    const code = error instanceof Error ? error.message : "invalid_state";
    sendError(
      res,
      400,
      code === "expired_state" ? "expired_state" : "invalid_state",
      "Invalid or expired state"
    );
    return;
  }

  let encryptedPayload: string;
  try {
    const tokens = await exchangeCodeForTokens(code);
    encryptedPayload = encryptTokenHandoff({
      state: owner,
      tokenBundle: tokens,
    });
  } catch {
    sendError(res, 500, "oauth_error", "Failed to exchange code for tokens");
    return;
  }

  const redirectTarget = process.env.MEDOXIE_REDIRECT_URL || "https://medoxie.com";
  const redirectUrl = new URL(redirectTarget);
  redirectUrl.searchParams.delete("withings");
  redirectUrl.searchParams.delete("withings_result");
  redirectUrl.hash = new URLSearchParams({
    withings: "success",
    withings_payload: encryptedPayload,
  }).toString();
  res.status(302).setHeader("Location", redirectUrl.toString());
  res.end();
}

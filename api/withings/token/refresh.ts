import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  rejectLargeBody,
  requireMethod,
  sendError,
  sendJson,
} from "../../../lib/withings/http";
import { verifyWithingsAuth } from "../../../lib/withings/auth";
import { refreshAccessToken, buildAuthorizeUrl } from "../../../lib/withings/oauth";
import { getTokens, setTokens, setState } from "../../../lib/withings/tokenStore";
import crypto from "crypto";

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
): Promise<void> {
  if (!requireMethod(req, res, "POST")) return;
  if (!rejectLargeBody(req, res, 1024)) return;

  let auth;
  try {
    auth = await verifyWithingsAuth(req.headers, "/token/refresh");
  } catch (error) {
    const code = error instanceof Error ? error.message : "auth_failed";
    if (code === "missing_auth_headers") {
      sendError(res, 401, "unauthorized", "Missing authentication headers");
      return;
    }
    if (code === "invalid_timestamp" || code === "timestamp_out_of_range") {
      sendError(res, 400, "invalid_request", "Invalid timestamp");
      return;
    }
    sendError(res, 401, "unauthorized", "Invalid signature");
    return;
  }

  // Use profileId to allow multiple profiles per wallet.
  const userId = auth.profileId.toLowerCase();

  const stored = await getTokens(userId);
  if (!stored) {
    // Generate OAuth URL for user to connect
    try {
      const state = crypto.randomUUID();
      await setState(state, userId, 10 * 60); // 10 minutes TTL
      const url = buildAuthorizeUrl(state);
      sendJson(res, 401, {
        error: "oauth_required",
        message: "Please connect your Withings account",
        url,
      });
      return;
    } catch (error) {
      console.error("Failed to generate OAuth URL:", {
        profileId: auth.profileId,
        error: error instanceof Error ? error.message : String(error),
      });
      sendError(res, 500, "server_error", "Failed to generate OAuth URL");
      return;
    }
  }

  try {
    const refreshed = await refreshAccessToken(stored.refresh_token);
    await setTokens(userId, refreshed);
    sendJson(res, 200, { ok: true, expires_at: refreshed.expires_at });
  } catch {
    sendError(res, 401, "reauth_required", "Refresh failed");
  }
}

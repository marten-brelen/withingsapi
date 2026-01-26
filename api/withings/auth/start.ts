import type { VercelRequest, VercelResponse } from "@vercel/node";
import crypto from "crypto";
import {
  enforceHttps,
  requireMethod,
  sendError,
  sendJson,
} from "../../../lib/withings/http";
import { verifyWithingsAuth } from "../../../lib/withings/auth";
import { buildAuthorizeUrl } from "../../../lib/withings/oauth";
import { setState } from "../../../lib/withings/tokenStore";
import { verifyLensProfileOwnership } from "../../../lib/withings/lensVerification";

const STATE_TTL_SECONDS = 10 * 60;

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
): Promise<void> {
  if (!requireMethod(req, res, "GET")) return;
  if (!enforceHttps(req, res)) return;

  let auth;
  try {
    auth = await verifyWithingsAuth(req.headers, "/auth/start");
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

  const profileOwned = await verifyLensProfileOwnership(
    auth.address,
    auth.profileId
  );
  if (!profileOwned) {
    sendError(
      res,
      403,
      "unauthorized",
      "Lens profile does not belong to wallet"
    );
    return;
  }

  const userId = auth.profileId.toLowerCase();
  const state = crypto.randomUUID();

  try {
    await setState(state, userId, STATE_TTL_SECONDS);
    const url = buildAuthorizeUrl(state);
    sendJson(res, 200, { url });
  } catch (error) {
    console.error("OAuth start failed:", {
      profileId: auth.profileId,
      address: auth.address,
      error: error instanceof Error ? error.message : String(error),
    });
    sendError(res, 500, "server_error", "Failed to start OAuth flow");
  }
}

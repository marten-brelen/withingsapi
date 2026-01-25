import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  rejectLargeBody,
  requireMethod,
  sendError,
  sendJson,
} from "../../../lib/withings/http";
import { verifyWithingsAuth } from "../../../lib/withings/auth";
import { refreshAccessToken } from "../../../lib/withings/oauth";
import { getTokens, setTokens } from "../../../lib/withings/tokenStore";
import { verifyLensProfileOwnership } from "../../../lib/withings/lensVerification";
import { resolveUserIdFromProfile } from "../../../lib/withings/userId";

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

  const userId = await resolveUserIdFromProfile(auth.profileId);
  if (!userId) {
    sendError(
      res,
      404,
      "user_not_found",
      "No Withings email found for this Lens profile"
    );
    return;
  }

  const stored = await getTokens(userId);
  if (!stored) {
    sendError(res, 401, "not_connected", "User is not connected");
    return;
  }

  try {
    const refreshed = await refreshAccessToken(stored.refresh_token);
    await setTokens(userId, refreshed);
    sendJson(res, 200, { ok: true, expires_at: refreshed.expires_at });
  } catch {
    sendError(res, 401, "reauth_required", "Refresh failed");
  }
}

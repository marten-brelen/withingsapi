import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  parseJsonBody,
  rejectLargeBody,
  requireMethod,
  sendError,
  sendJson,
} from "../../../lib/withings/http";
import { refreshAccessToken } from "../../../lib/withings/oauth";
import { getTokens, setTokens } from "../../../lib/withings/tokenStore";

function extractUserId(req: VercelRequest): string | null {
  if (typeof req.query.user_id === "string" && req.query.user_id.trim()) {
    return req.query.user_id.trim();
  }
  return null;
}

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
): Promise<void> {
  if (!requireMethod(req, res, "POST")) return;
  if (!rejectLargeBody(req, res, 1024)) return;

  let userId = extractUserId(req);
  if (!userId) {
    const body = await parseJsonBody(req);
    if (body && typeof body.user_id === "string") {
      userId = body.user_id.trim();
    }
  }

  if (!userId) {
    sendError(res, 400, "invalid_request", "user_id is required");
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

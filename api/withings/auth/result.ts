import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  parseJsonBody,
  rejectLargeBody,
  requireMethod,
  sendError,
  sendJson,
} from "../../../lib/withings/http";
import { verifyWithingsAuth } from "../../../lib/withings/auth";
import { consumeOAuthResult } from "../../../lib/withings/tokenStore";

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
): Promise<void> {
  if (!requireMethod(req, res, "POST")) return;
  if (!rejectLargeBody(req, res, 2048)) return;

  let auth;
  try {
    auth = await verifyWithingsAuth(req.headers, "/auth/result");
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

  const body = await parseJsonBody(req);
  const resultId = typeof body?.resultId === "string" ? body.resultId.trim() : "";
  if (!resultId) {
    sendError(res, 400, "invalid_request", "resultId is required");
    return;
  }

  const result = await consumeOAuthResult(resultId, {
    address: auth.address,
    profileId: auth.profileId,
  });

  if (result.kind === "missing") {
    sendError(res, 404, "result_not_found", "OAuth result was already consumed or expired");
    return;
  }

  if (result.kind === "forbidden") {
    sendError(res, 403, "forbidden", "OAuth result belongs to a different wallet/profile");
    return;
  }

  sendJson(res, 200, { tokenBundle: result.tokenBundle });
}

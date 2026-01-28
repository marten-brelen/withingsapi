import type { VercelRequest, VercelResponse } from "@vercel/node";
import { getSleepSummary, WithingsError } from "../../lib/withings/client";
import { withingsRequestWithRetry } from "../../lib/withings/data";
import { verifyWithingsAuth } from "../../lib/withings/auth";
import { buildAuthorizeUrl } from "../../lib/withings/oauth";
import { setState } from "../../lib/withings/tokenStore";
import crypto from "crypto";
import {
  getRequiredDateParam,
  requireMethod,
  sendError,
  sendJson,
} from "../../lib/withings/http";

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
): Promise<void> {
  if (!requireMethod(req, res, "GET")) return;

  let auth;
  try {
    auth = await verifyWithingsAuth(req.headers, "/sleep");
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

  const startdate = getRequiredDateParam(req, res, "startdate");
  const enddate = getRequiredDateParam(req, res, "enddate");
  if (!startdate || !enddate) return;

  try {
    const result = await withingsRequestWithRetry(userId, (accessToken) =>
      getSleepSummary(accessToken, startdate, enddate)
    );
    if (
      typeof result === "object" &&
      result &&
      ("kind" in result &&
        (result.kind === "not_connected" || result.kind === "reauth_required"))
    ) {
      if (result.kind === "not_connected" || result.kind === "reauth_required") {
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
    }
    sendJson(res, 200, { data: result });
  } catch (error) {
    if (error instanceof WithingsError) {
      sendError(
        res,
        502,
        "withings_error",
        `${error.message}${error.status ? ` (status ${error.status})` : ""}`
      );
      return;
    }
    sendError(res, 502, "withings_error", "Withings API error");
  }
}

import type { VercelRequest, VercelResponse } from "@vercel/node";
import crypto from "crypto";
import { getMeasures, WithingsError } from "../../lib/withings/client";
import { withingsRequestWithRetry } from "../../lib/withings/data";
import { verifyWithingsAuth } from "../../lib/withings/auth";
import { buildAuthorizeUrl } from "../../lib/withings/oauth";
import { setState } from "../../lib/withings/tokenStore";
import {
  getRequiredDateFromQueryOrBody,
  readTokenPayload,
} from "../../lib/withings/tokenPayload";
import {
  rejectLargeBody,
  requireMethod,
  sendError,
  sendJson,
} from "../../lib/withings/http";

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
): Promise<void> {
  if (!requireMethod(req, res, "POST")) return;
  if (!rejectLargeBody(req, res, 16 * 1024)) return;

  let auth;
  try {
    auth = await verifyWithingsAuth(req.headers, "/measure");
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

  const startdate = await getRequiredDateFromQueryOrBody(req, res, "startdate");
  const enddate = await getRequiredDateFromQueryOrBody(req, res, "enddate");
  if (!startdate || !enddate) return;

  const payload = await readTokenPayload(req, res, { sendMissingError: false });
  if (!payload) {
    try {
      const state = crypto.randomUUID();
      await setState(
        state,
        { address: auth.address, profileId: auth.profileId },
        10 * 60
      );
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
    const result = await withingsRequestWithRetry(payload.tokenBundle, (accessToken) =>
      getMeasures(accessToken, startdate, enddate)
    );
    if (result.kind === "reauth_required") {
      sendError(res, 401, "reauth_required", "Please reconnect your Withings account");
      return;
    }
    sendJson(res, 200, {
      data: result.data,
      ...(result.refreshed ? { tokenBundle: result.tokenBundle } : {}),
    });
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

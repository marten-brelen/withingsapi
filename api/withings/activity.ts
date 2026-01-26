import type { VercelRequest, VercelResponse } from "@vercel/node";
import { getActivity, WithingsError } from "../../lib/withings/client";
import { withingsRequestWithRetry } from "../../lib/withings/data";
import { verifyWithingsAuth } from "../../lib/withings/auth";
import { verifyLensProfileOwnership } from "../../lib/withings/lensVerification";
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
    auth = await verifyWithingsAuth(req.headers, "/activity");
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

  const startdate = getRequiredDateParam(req, res, "startdate");
  const enddate = getRequiredDateParam(req, res, "enddate");
  if (!startdate || !enddate) return;

  try {
    const result = await withingsRequestWithRetry(userId, (accessToken) =>
      getActivity(accessToken, startdate, enddate)
    );
    if (
      typeof result === "object" &&
      result &&
      ("kind" in result &&
        (result.kind === "not_connected" || result.kind === "reauth_required"))
    ) {
      if (result.kind === "not_connected") {
        sendError(res, 401, "not_connected", "User is not connected");
        return;
      }
      sendError(res, 401, "reauth_required", "Re-auth required");
      return;
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

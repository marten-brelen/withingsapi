import type { VercelRequest, VercelResponse } from "@vercel/node";
import { getMeasures, WithingsError } from "../../lib/withings/client";
import { withingsRequestWithRetry } from "../../lib/withings/data";
import {
  getRequiredDateParam,
  getRequiredQueryParam,
  requireMethod,
  sendError,
  sendJson,
} from "../../lib/withings/http";

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
): Promise<void> {
  if (!requireMethod(req, res, "GET")) return;

  const userId = getRequiredQueryParam(req, res, "user_id");
  if (!userId) return;
  const startdate = getRequiredDateParam(req, res, "startdate");
  const enddate = getRequiredDateParam(req, res, "enddate");
  if (!startdate || !enddate) return;

  try {
    const result = await withingsRequestWithRetry(userId, (accessToken) =>
      getMeasures(accessToken, startdate, enddate)
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

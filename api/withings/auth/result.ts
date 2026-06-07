import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  rejectLargeBody,
  requireMethod,
  sendError,
} from "../../../lib/withings/http";

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
): Promise<void> {
  if (!requireMethod(req, res, "POST")) return;
  if (!rejectLargeBody(req, res, 2048)) return;

  sendError(
    res,
    410,
    "oauth_result_removed",
    "OAuth result polling has been replaced by encrypted callback payloads"
  );
}

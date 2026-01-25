import type { VercelRequest, VercelResponse } from "@vercel/node";
import crypto from "crypto";
import {
  enforceHttps,
  getRequiredQueryParam,
  requireMethod,
  sendError,
  sendJson,
} from "../../../lib/withings/http";
import { buildAuthorizeUrl } from "../../../lib/withings/oauth";
import { setState } from "../../../lib/withings/tokenStore";

const STATE_TTL_SECONDS = 10 * 60;

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
): Promise<void> {
  if (!requireMethod(req, res, "GET")) return;
  if (!enforceHttps(req, res)) return;

  const userId = getRequiredQueryParam(req, res, "user_id");
  if (!userId) return;

  const state = crypto.randomUUID();

  try {
    await setState(state, userId, STATE_TTL_SECONDS);
    const url = buildAuthorizeUrl(state);
    sendJson(res, 200, { url });
  } catch (error) {
    sendError(res, 500, "server_error", "Failed to start OAuth flow");
  }
}

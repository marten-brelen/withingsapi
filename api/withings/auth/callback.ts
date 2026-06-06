import type { VercelRequest, VercelResponse } from "@vercel/node";
import crypto from "crypto";
import {
  enforceHttps,
  requireMethod,
  sendError,
} from "../../../lib/withings/http";
import { exchangeCodeForTokens } from "../../../lib/withings/oauth";
import { consumeState, setOAuthResult } from "../../../lib/withings/tokenStore";

const RESULT_TTL_SECONDS = 10 * 60;

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
): Promise<void> {
  if (!requireMethod(req, res, "GET")) return;
  if (!enforceHttps(req, res)) return;

  const state = typeof req.query.state === "string" ? req.query.state : null;
  const code = typeof req.query.code === "string" ? req.query.code : null;

  if (!state || !code) {
    sendError(res, 400, "invalid_request", "state and code are required");
    return;
  }

  const owner = await consumeState(state);
  if (!owner) {
    sendError(res, 400, "invalid_state", "Invalid or expired state");
    return;
  }

  let resultId: string;
  try {
    const tokens = await exchangeCodeForTokens(code);
    resultId = crypto.randomUUID();
    await setOAuthResult(
      resultId,
      {
        ...owner,
        tokenBundle: tokens,
        createdAt: Date.now(),
      },
      RESULT_TTL_SECONDS
    );
  } catch {
    sendError(res, 500, "oauth_error", "Failed to exchange code for tokens");
    return;
  }

  const redirectTarget =
    process.env.MEDOXIE_REDIRECT_URL || "https://medoxie.com?withings=success";
  const redirectUrl = new URL(redirectTarget);
  redirectUrl.searchParams.set("withings", "success");
  redirectUrl.searchParams.set("withings_result", resultId);
  res.status(302).setHeader("Location", redirectUrl.toString());
  res.end();
}

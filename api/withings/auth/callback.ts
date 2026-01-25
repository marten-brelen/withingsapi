import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  enforceHttps,
  requireMethod,
  sendError,
} from "../../../lib/withings/http";
import { exchangeCodeForTokens } from "../../../lib/withings/oauth";
import { consumeState, setTokens } from "../../../lib/withings/tokenStore";

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

  const userId = await consumeState(state);
  if (!userId) {
    sendError(res, 400, "invalid_state", "Invalid or expired state");
    return;
  }

  try {
    const tokens = await exchangeCodeForTokens(code);
    await setTokens(userId, tokens);
  } catch {
    sendError(res, 500, "oauth_error", "Failed to exchange code for tokens");
    return;
  }

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.status(200).send(
    [
      "<!doctype html>",
      "<html>",
      "<head><title>Withings Connected</title></head>",
      "<body>",
      "<p>Withings connected. You can return to Medoxie.</p>",
      "</body>",
      "</html>",
    ].join("")
  );
}

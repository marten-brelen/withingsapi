import type { VercelRequest, VercelResponse } from "@vercel/node";
import crypto from "crypto";
import {
  enforceHttps,
  requireMethod,
  sendError,
  sendJson,
} from "../../../lib/withings/http";
import { verifyWithingsAuth } from "../../../lib/withings/auth";
import { buildAuthorizeUrl } from "../../../lib/withings/oauth";
import { setState } from "../../../lib/withings/tokenStore";
import { verifyLensProfileOwnership } from "../../../lib/withings/lensVerification";

const STATE_TTL_SECONDS = 10 * 60;

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
): Promise<void> {
  console.log("Withings auth/start called:", {
    method: req.method,
    hasHeaders: !!req.headers,
    headerKeys: Object.keys(req.headers),
  });

  if (!requireMethod(req, res, "GET")) return;
  if (!enforceHttps(req, res)) return;

  let auth;
  try {
    auth = await verifyWithingsAuth(req.headers, "/auth/start");
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

  // Wrap Lens verification in try-catch
  let profileOwned: boolean;
  try {
    profileOwned = await verifyLensProfileOwnership(
      auth.address,
      auth.profileId
    );
  } catch (error) {
    console.error("Lens verification failed:", {
      profileId: auth.profileId,
      address: auth.address,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    sendError(res, 500, "server_error", "Failed to verify Lens profile");
    return;
  }
  if (!profileOwned) {
    sendError(
      res,
      403,
      "unauthorized",
      "Lens profile does not belong to wallet"
    );
    return;
  }

  // Validate environment variables before proceeding
  const requiredEnvVars = [
    "WITHINGS_CLIENT_ID",
    "WITHINGS_REDIRECT_URI",
    "TOKEN_STORE_URL",
    "TOKEN_STORE_TOKEN",
  ];
  const missingEnvVars = requiredEnvVars.filter(
    (name) => !process.env[name]
  );
  if (missingEnvVars.length > 0) {
    console.error("Missing environment variables:", missingEnvVars);
    sendError(
      res,
      500,
      "server_error",
      "Server configuration error: missing environment variables"
    );
    return;
  }

  const userId = auth.profileId.toLowerCase();
  const state = crypto.randomUUID();

  try {
    await setState(state, userId, STATE_TTL_SECONDS);
  } catch (error) {
    console.error("Failed to set state in Redis:", {
      profileId: auth.profileId,
      address: auth.address,
      state,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    sendError(res, 500, "server_error", "Failed to initialize OAuth state");
    return;
  }

  try {
    const url = buildAuthorizeUrl(state);
    sendJson(res, 200, { url });
  } catch (error) {
    console.error("Failed to build OAuth URL:", {
      profileId: auth.profileId,
      address: auth.address,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    sendError(res, 500, "server_error", "Failed to build OAuth authorization URL");
  }
}

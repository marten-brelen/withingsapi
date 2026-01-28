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
  try {
    console.log("Withings auth/start called:", {
      method: req.method,
      hasHeaders: !!req.headers,
      headerKeys: Object.keys(req.headers),
      url: req.url,
    });

    if (!requireMethod(req, res, "GET")) return;
    if (!enforceHttps(req, res)) return;

  let auth;
  try {
    auth = await verifyWithingsAuth(req.headers, "/auth/start");
  } catch (error) {
    const code = error instanceof Error ? error.message : "auth_failed";
    console.error("Auth verification failed:", {
      code,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });

    if (code === "missing_auth_headers") {
      sendError(res, 401, "unauthorized", "Missing authentication headers");
      return;
    }
    if (code === "invalid_message_encoding") {
      sendError(res, 400, "invalid_request", "Invalid message encoding");
      return;
    }
    if (code === "invalid_message_format") {
      sendError(res, 400, "invalid_request", "Invalid message format");
      return;
    }
    if (
      code === "address_mismatch" ||
      code === "profileid_mismatch" ||
      code === "timestamp_mismatch" ||
      code === "path_mismatch"
    ) {
      sendError(res, 400, "invalid_request", "Message fields do not match headers");
      return;
    }
    if (code === "invalid_timestamp" || code === "timestamp_out_of_range") {
      sendError(res, 400, "invalid_request", "Invalid timestamp");
      return;
    }
    if (code === "invalid_signature_format") {
      sendError(res, 400, "invalid_request", "Invalid signature format");
      return;
    }
    if (code === "invalid_signature" || code === "signature_mismatch") {
      sendError(res, 401, "unauthorized", "Invalid signature");
      return;
    }
    // Unknown error - return 500 with details
    console.error("Unexpected auth error:", code);
    sendError(res, 500, "server_error", `Authentication failed: ${code}`);
    return;
  }

  console.log("Starting Lens verification:", {
    address: auth.address,
    profileId: auth.profileId,
  });

  let profileOwned: boolean;
  try {
    profileOwned = await verifyLensProfileOwnership(
      auth.address,
      auth.profileId
    );
    console.log("Lens verification result:", {
      profileId: auth.profileId,
      address: auth.address,
      owned: profileOwned,
    });
  } catch (error) {
    console.error("Lens verification exception:", {
      profileId: auth.profileId,
      address: auth.address,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    sendError(res, 500, "server_error", "Failed to verify Lens profile");
    return;
  }
  if (!profileOwned) {
    console.warn("Lens profile ownership check failed:", {
      profileId: auth.profileId,
      address: auth.address,
    });
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

  // Use profileId to allow multiple profiles per wallet.
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
  } catch (error) {
    // Catch any unexpected errors
    console.error("Unexpected error in auth/start handler:", {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    sendError(res, 500, "server_error", "Internal server error");
  }
}

import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  enforceHttps,
  parseJsonBody,
  rejectLargeBody,
  requireMethod,
  sendError,
  sendJson,
} from "../../../lib/withings/http";
import { verifyWithingsAuth } from "../../../lib/withings/auth";
import {
  buildAuthorizeUrl,
  validateOAuthEnvVars,
} from "../../../lib/withings/oauth";
import {
  assertOAuthHandoffConfigured,
  parseOAuthStartRequest,
  sealOAuthState,
} from "../../../lib/withings/oauthHandoff";

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
): Promise<void> {
  try {
    console.log("Withings auth/start called:", {
      method: req.method,
      url: req.url,
    });

    if (!requireMethod(req, res, "POST")) return;
    if (!enforceHttps(req, res)) return;
    if (!rejectLargeBody(req, res, 4096)) return;

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
        sendError(
          res,
          400,
          "invalid_request",
          "Message fields do not match headers"
        );
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
      console.error("Unexpected auth error:", code);
      sendError(res, 500, "server_error", `Authentication failed: ${code}`);
      return;
    }

    try {
      validateOAuthEnvVars();
      assertOAuthHandoffConfigured();
    } catch (error) {
      console.error("Missing OAuth handoff configuration:", {
        error: error instanceof Error ? error.message : String(error),
      });
      sendError(
        res,
        500,
        "server_error",
        "Server configuration error: missing environment variables"
      );
      return;
    }

    const startRequest = parseOAuthStartRequest(await parseJsonBody(req));
    if (!startRequest) {
      sendError(
        res,
        400,
        "invalid_request",
        "A valid Medoxie OAuth callback key is required"
      );
      return;
    }

    try {
      const state = sealOAuthState({
        address: auth.address,
        profileId: auth.profileId,
        callbackNonce: startRequest.callbackNonce,
        callbackPublicKey: startRequest.callbackPublicKey,
      });
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
  } catch (error) {
    // Catch any unexpected errors
    console.error("Unexpected error in auth/start handler:", {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    sendError(res, 500, "server_error", "Internal server error");
  }
}

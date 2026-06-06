import type { VercelRequest, VercelResponse } from "@vercel/node";
import { getRequiredDateParam, parseJsonBody, sendError } from "./http";
import { TokenBundle } from "./tokenStore";

export type TokenPayload = {
  tokenBundle: TokenBundle;
};

export async function readTokenPayload(
  req: VercelRequest,
  res: VercelResponse,
  options: { sendMissingError?: boolean } = {}
): Promise<TokenPayload | null> {
  const body = await parseJsonBody(req);
  const tokenBundle = parseTokenBundle(body?.tokenBundle);
  if (!tokenBundle) {
    if (options.sendMissingError !== false) {
      sendError(
        res,
        400,
        "missing_token_bundle",
        "A decrypted Withings token bundle is required in the request body"
      );
    }
    return null;
  }
  return { tokenBundle };
}

export async function getRequiredDateFromQueryOrBody(
  req: VercelRequest,
  res: VercelResponse,
  name: "startdate" | "enddate"
): Promise<string | null> {
  const queryValue = req.query[name];
  if (typeof queryValue === "string" && queryValue.trim().length > 0) {
    return getRequiredDateParam(req, res, name);
  }

  const body = await parseJsonBody(req);
  const value = body?.[name];
  if (typeof value !== "string" || value.trim().length === 0) {
    sendError(res, 400, "invalid_request", `${name} is required`);
    return null;
  }
  if (!/^\d+$/.test(value.trim())) {
    sendError(res, 400, "invalid_request", `${name} must be a unix timestamp`);
    return null;
  }
  return value.trim();
}

function parseTokenBundle(value: unknown): TokenBundle | null {
  if (!value || typeof value !== "object") {
    return null;
  }
  const candidate = value as Partial<TokenBundle>;
  if (
    typeof candidate.access_token !== "string" ||
    candidate.access_token.length === 0 ||
    typeof candidate.refresh_token !== "string" ||
    candidate.refresh_token.length === 0 ||
    typeof candidate.expires_at !== "number" ||
    !Number.isFinite(candidate.expires_at) ||
    typeof candidate.scope !== "string"
  ) {
    return null;
  }
  return {
    access_token: candidate.access_token,
    refresh_token: candidate.refresh_token,
    expires_at: candidate.expires_at,
    scope: candidate.scope,
  };
}

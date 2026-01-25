import { WithingsError } from "./client";
import { refreshAccessToken } from "./oauth";
import { getTokens, setTokens, TokenBundle } from "./tokenStore";

const REFRESH_WINDOW_MS = 30_000;

type TokenStatus =
  | { kind: "ok"; tokens: TokenBundle }
  | { kind: "not_connected" }
  | { kind: "reauth_required" };

async function ensureTokens(userId: string): Promise<TokenStatus> {
  const tokens = await getTokens(userId);
  if (!tokens) {
    return { kind: "not_connected" };
  }
  if (tokens.expires_at > Date.now() + REFRESH_WINDOW_MS) {
    return { kind: "ok", tokens };
  }
  try {
    const refreshed = await refreshAccessToken(tokens.refresh_token);
    await setTokens(userId, refreshed);
    return { kind: "ok", tokens: refreshed };
  } catch {
    return { kind: "reauth_required" };
  }
}

export async function withingsRequestWithRetry<T>(
  userId: string,
  requestFn: (accessToken: string) => Promise<T>
): Promise<T | TokenStatus> {
  const status = await ensureTokens(userId);
  if (status.kind !== "ok") {
    return status;
  }

  try {
    return await requestFn(status.tokens.access_token);
  } catch (error) {
    const isAuthError =
      error instanceof WithingsError &&
      (error.status === 401 || error.code === "invalid_token");
    if (!isAuthError) {
      throw error;
    }
    try {
      const refreshed = await refreshAccessToken(status.tokens.refresh_token);
      await setTokens(userId, refreshed);
      return await requestFn(refreshed.access_token);
    } catch {
      return { kind: "reauth_required" };
    }
  }
}

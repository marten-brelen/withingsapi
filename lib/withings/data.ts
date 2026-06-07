import { WithingsError } from "./client";
import { refreshAccessToken } from "./oauth";
import { TokenBundle } from "./tokenTypes";

const REFRESH_WINDOW_MS = 30_000;

export type WithingsDataResult<T> =
  | { kind: "ok"; data: T; tokenBundle: TokenBundle; refreshed: boolean }
  | { kind: "reauth_required" };

async function ensureTokens(tokens: TokenBundle): Promise<
  | { kind: "ok"; tokenBundle: TokenBundle; refreshed: boolean }
  | { kind: "reauth_required" }
> {
  if (tokens.expires_at > Date.now() + REFRESH_WINDOW_MS) {
    return { kind: "ok", tokenBundle: tokens, refreshed: false };
  }
  try {
    const refreshed = await refreshAccessToken(tokens.refresh_token);
    return { kind: "ok", tokenBundle: refreshed, refreshed: true };
  } catch {
    return { kind: "reauth_required" };
  }
}

export async function withingsRequestWithRetry<T>(
  tokens: TokenBundle,
  requestFn: (accessToken: string) => Promise<T>
): Promise<WithingsDataResult<T>> {
  const status = await ensureTokens(tokens);
  if (status.kind !== "ok") {
    return status;
  }

  try {
    const data = await requestFn(status.tokenBundle.access_token);
    return {
      kind: "ok",
      data,
      tokenBundle: status.tokenBundle,
      refreshed: status.refreshed,
    };
  } catch (error) {
    const isAuthError =
      error instanceof WithingsError &&
      (error.status === 401 || error.code === "invalid_token");
    if (!isAuthError) {
      throw error;
    }
    try {
      const refreshed = await refreshAccessToken(status.tokenBundle.refresh_token);
      const data = await requestFn(refreshed.access_token);
      return {
        kind: "ok",
        data,
        tokenBundle: refreshed,
        refreshed: true,
      };
    } catch {
      return { kind: "reauth_required" };
    }
  }
}

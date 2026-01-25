import { refreshAccessToken } from "./oauth";
import { getTokens, setTokens, TokenBundle } from "./tokenStore";

const REFRESH_WINDOW_MS = 30_000;

export async function getValidTokens(
  userId: string
): Promise<TokenBundle | null> {
  const existing = await getTokens(userId);
  if (!existing) {
    return null;
  }
  if (existing.expires_at > Date.now() + REFRESH_WINDOW_MS) {
    return existing;
  }
  try {
    const refreshed = await refreshAccessToken(existing.refresh_token);
    await setTokens(userId, refreshed);
    return refreshed;
  } catch {
    return null;
  }
}

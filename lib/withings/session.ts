import { refreshAccessToken } from "./oauth";
import { TokenBundle } from "./tokenTypes";

const REFRESH_WINDOW_MS = 30_000;

export async function getValidTokens(
  tokens: TokenBundle | null
): Promise<TokenBundle | null> {
  if (!tokens) {
    return null;
  }
  if (tokens.expires_at > Date.now() + REFRESH_WINDOW_MS) {
    return tokens;
  }
  try {
    return await refreshAccessToken(tokens.refresh_token);
  } catch {
    return null;
  }
}

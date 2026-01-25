import { TokenBundle } from "./tokenStore";

const DEFAULT_SCOPES = ["user.metrics", "user.activity", "user.sleepevents"];

type OAuthTokenResponse = {
  status?: number;
  error?: string;
  error_description?: string;
  body?: {
    access_token: string;
    refresh_token: string;
    expires_in: number;
    scope: string;
  };
};

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function ensureHttpsRedirect(redirectUri: string): void {
  if (process.env.NODE_ENV === "production" && !redirectUri.startsWith("https://")) {
    throw new Error("WITHINGS_REDIRECT_URI must use https in production");
  }
}

export function getWithingsApiBaseUrl(): string {
  return (
    process.env.WITHINGS_API_BASE_URL ||
    process.env.NEXT_PUBLIC_WITHINS_SERVER_URL ||
    "https://wbsapi.withings.net"
  );
}

export function getWithingsOauthBaseUrl(): string {
  return process.env.WITHINGS_OAUTH_BASE_URL || "https://account.withings.com";
}

export function getOAuthScopes(): string {
  return process.env.WITHINGS_SCOPES || DEFAULT_SCOPES.join(",");
}

export function buildAuthorizeUrl(state: string): string {
  const clientId = requiredEnv("WITHINGS_CLIENT_ID");
  const redirectUri = requiredEnv("WITHINGS_REDIRECT_URI");
  ensureHttpsRedirect(redirectUri);
  const scope = getOAuthScopes();
  const base = getWithingsOauthBaseUrl();
  const url = new URL("/oauth2_user/authorize2", base);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", scope);
  url.searchParams.set("state", state);
  return url.toString();
}

function parseTokenResponse(data: OAuthTokenResponse): TokenBundle {
  if (data.status && data.status !== 0) {
    throw new Error(
      `withings_error:${data.status}:${data.error || "unknown_error"}`
    );
  }
  if (!data.body?.access_token || !data.body?.refresh_token) {
    throw new Error("withings_error:invalid_token_response");
  }
  const expiresAt = Date.now() + data.body.expires_in * 1000;
  return {
    access_token: data.body.access_token,
    refresh_token: data.body.refresh_token,
    expires_at: expiresAt,
    scope: data.body.scope || getOAuthScopes(),
  };
}

export async function exchangeCodeForTokens(code: string): Promise<TokenBundle> {
  const clientId = requiredEnv("WITHINGS_CLIENT_ID");
  const clientSecret = requiredEnv("WITHINGS_CLIENT_SECRET");
  const redirectUri = requiredEnv("WITHINGS_REDIRECT_URI");
  ensureHttpsRedirect(redirectUri);
  const url = new URL("/v2/oauth2", getWithingsApiBaseUrl());
  const body = new URLSearchParams({
    action: "requesttoken",
    grant_type: "authorization_code",
    client_id: clientId,
    client_secret: clientSecret,
    code,
    redirect_uri: redirectUri,
  });

  const response = await fetch(url.toString(), {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: body.toString(),
  });

  const data = (await response.json()) as OAuthTokenResponse;
  return parseTokenResponse(data);
}

export async function refreshAccessToken(
  refreshToken: string
): Promise<TokenBundle> {
  const clientId = requiredEnv("WITHINGS_CLIENT_ID");
  const clientSecret = requiredEnv("WITHINGS_CLIENT_SECRET");
  const url = new URL("/v2/oauth2", getWithingsApiBaseUrl());
  const body = new URLSearchParams({
    action: "requesttoken",
    grant_type: "refresh_token",
    client_id: clientId,
    client_secret: clientSecret,
    refresh_token: refreshToken,
  });

  const response = await fetch(url.toString(), {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: body.toString(),
  });

  const data = (await response.json()) as OAuthTokenResponse;
  return parseTokenResponse(data);
}

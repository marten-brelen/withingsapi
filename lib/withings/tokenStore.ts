import { Redis } from "@upstash/redis";

export type TokenBundle = {
  access_token: string;
  refresh_token: string;
  expires_at: number;
  scope: string;
};

export type OAuthOwner = {
  address: string;
  profileId: string;
};

export type OAuthResult = OAuthOwner & {
  tokenBundle: TokenBundle;
  createdAt: number;
};

export type OAuthResultConsumeStatus =
  | { kind: "ok"; tokenBundle: TokenBundle }
  | { kind: "missing" }
  | { kind: "forbidden" };

const STATE_KEY_PREFIX = "withings:state:";
const RESULT_KEY_PREFIX = "withings:oauth-result:";

let redisClient: Redis | null = null;

function getRedis(): Redis {
  if (redisClient) {
    return redisClient;
  }
  const url = process.env.TOKEN_STORE_URL;
  const token = process.env.TOKEN_STORE_TOKEN;
  if (!url || !token) {
    throw new Error(
      `Redis configuration missing: TOKEN_STORE_URL=${!!url}, TOKEN_STORE_TOKEN=${!!token}`
    );
  }
  try {
    redisClient = new Redis({ url, token });
    return redisClient;
  } catch (error) {
    throw new Error(
      `Failed to initialize Redis client: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

export async function setState(
  state: string,
  owner: OAuthOwner,
  ttlSeconds: number
): Promise<void> {
  const redis = getRedis();
  const key = `${STATE_KEY_PREFIX}${state}`;
  const ttl = Math.max(1, Math.floor(ttlSeconds));
  await redis.set(key, normalizeOwner(owner), { ex: ttl });
}

export async function consumeState(state: string): Promise<OAuthOwner | null> {
  const redis = getRedis();
  const key = `${STATE_KEY_PREFIX}${state}`;
  const owner = await redis.get<OAuthOwner>(key);
  if (owner) {
    await redis.del(key);
  }
  return owner ? normalizeOwner(owner) : null;
}

export async function setOAuthResult(
  resultId: string,
  result: OAuthResult,
  ttlSeconds: number
): Promise<void> {
  const redis = getRedis();
  const key = `${RESULT_KEY_PREFIX}${resultId}`;
  const ttl = Math.max(1, Math.floor(ttlSeconds));
  await redis.set(
    key,
    {
      ...normalizeOwner(result),
      tokenBundle: result.tokenBundle,
      createdAt: result.createdAt,
    },
    { ex: ttl }
  );
}

export async function consumeOAuthResult(
  resultId: string,
  owner: OAuthOwner
): Promise<OAuthResultConsumeStatus> {
  const redis = getRedis();
  const key = `${RESULT_KEY_PREFIX}${resultId}`;
  const result = await redis.get<OAuthResult>(key);
  if (!result) {
    return { kind: "missing" };
  }

  const expected = normalizeOwner(owner);
  const actual = normalizeOwner(result);
  if (
    actual.address !== expected.address ||
    actual.profileId !== expected.profileId
  ) {
    return { kind: "forbidden" };
  }

  await redis.del(key);
  return { kind: "ok", tokenBundle: result.tokenBundle };
}

function normalizeOwner(owner: OAuthOwner): OAuthOwner {
  return {
    address: owner.address.toLowerCase(),
    profileId: owner.profileId.toLowerCase(),
  };
}

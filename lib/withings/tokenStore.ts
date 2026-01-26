import { Redis } from "@upstash/redis";

export type TokenBundle = {
  access_token: string;
  refresh_token: string;
  expires_at: number;
  scope: string;
};

const TOKEN_KEY_PREFIX = "withings:tokens:";
const STATE_KEY_PREFIX = "withings:state:";

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

export async function getTokens(userId: string): Promise<TokenBundle | null> {
  const redis = getRedis();
  const key = `${TOKEN_KEY_PREFIX}${userId}`;
  const data = await redis.get<TokenBundle>(key);
  return data ?? null;
}

export async function setTokens(
  userId: string,
  tokens: TokenBundle
): Promise<void> {
  const redis = getRedis();
  const key = `${TOKEN_KEY_PREFIX}${userId}`;
  await redis.set(key, tokens);
}

export async function setState(
  state: string,
  userId: string,
  ttlSeconds: number
): Promise<void> {
  const redis = getRedis();
  const key = `${STATE_KEY_PREFIX}${state}`;
  const ttl = Math.max(1, Math.floor(ttlSeconds));
  await redis.set(key, userId, { ex: ttl });
}

export async function consumeState(state: string): Promise<string | null> {
  const redis = getRedis();
  const key = `${STATE_KEY_PREFIX}${state}`;
  const userId = await redis.get<string>(key);
  if (userId) {
    await redis.del(key);
  }
  return userId ?? null;
}

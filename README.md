# Withings Server (Vercel)

Serverless API routes for Withings OAuth and data access for Medoxie.

## Environment variables

- `WITHINGS_CLIENT_ID`
- `WITHINGS_CLIENT_SECRET`
- `WITHINGS_REDIRECT_URI`
- `WITHINGS_API_BASE_URL` (optional, defaults to `https://wbsapi.withings.net`)
- `WITHINGS_OAUTH_BASE_URL` (optional, defaults to `https://account.withings.com`)
- `WITHINGS_SCOPES` (optional, defaults to `user.metrics,user.activity,user.sleepevents`)
- `TOKEN_STORE_URL` (Upstash Redis REST URL)
- `TOKEN_STORE_TOKEN` (Upstash Redis REST token; used only for short-lived OAuth state/results)
- `MEDOXIE_REDIRECT_URL` (optional, defaults to `https://medoxie.com?withings=success`)
- `LENS_ENVIRONMENT` (optional, `development` or `production`, defaults to `production`)

## Authentication

All `/api/withings/*` endpoints require Medoxie wallet signature headers. The server
verifies:

1. Wallet signature is valid
2. Lens profile belongs to the wallet
3. Withings email is read from Lens profile metadata

**Important:** `user_id` query parameters are ignored. Identity is derived from the
verified Lens profile.

### Required headers

- `x-medoxie-address`
- `x-medoxie-profile-id`
- `x-medoxie-timestamp`
- `x-medoxie-message`
- `x-medoxie-signature`

### Signed message format

```
Medoxie Withings API Access
address: 0x1234...
profileId: 0x5678...
timestamp: 1234567890123
path: /sleep
```

## Endpoints

- `GET /api/health`
- `GET /api/withings/auth/start`
- `GET /api/withings/auth/callback`
- `POST /api/withings/auth/result`
- `POST /api/withings/token/refresh`
- `POST /api/withings/sleep`
- `POST /api/withings/measure`
- `POST /api/withings/activity`

OAuth callback stores a one-time encrypted-result handoff in Redis with a short TTL and redirects
to Medoxie with `withings_result=<opaque-id>`. Medoxie must consume that result once through
`/auth/result`, encrypt the returned token bundle client-side, and include the decrypted
`tokenBundle` in subsequent token-bearing request bodies. The server must not write long-lived
`withings:tokens:*` keys.

## Example curl

```bash
# Health
curl https://your-vercel-domain.com/api/health

# Auth headers (example placeholders)
ADDRESS=0x1234...
PROFILE_ID=0x5678...
TIMESTAMP=1234567890123
SIGNATURE=0xabc...

# Start OAuth
curl "https://your-vercel-domain.com/api/withings/auth/start" \
  -H "x-medoxie-address: ${ADDRESS}" \
  -H "x-medoxie-profile-id: ${PROFILE_ID}" \
  -H "x-medoxie-timestamp: ${TIMESTAMP}" \
  -H "x-medoxie-message: Medoxie Withings API Access
address: ${ADDRESS}
profileId: ${PROFILE_ID}
timestamp: ${TIMESTAMP}
path: /auth/start" \
  -H "x-medoxie-signature: ${SIGNATURE}"

# Refresh token
curl -X POST "https://your-vercel-domain.com/api/withings/token/refresh" \
  -H "x-medoxie-address: ${ADDRESS}" \
  -H "x-medoxie-profile-id: ${PROFILE_ID}" \
  -H "x-medoxie-timestamp: ${TIMESTAMP}" \
  -H "x-medoxie-message: Medoxie Withings API Access
address: ${ADDRESS}
profileId: ${PROFILE_ID}
timestamp: ${TIMESTAMP}
path: /token/refresh" \
  -H "x-medoxie-signature: ${SIGNATURE}" \
  -H "Content-Type: application/json" \
  --data '{"tokenBundle":{"access_token":"...","refresh_token":"...","expires_at":1706745600000,"scope":"user.metrics,user.activity,user.sleepevents"}}'

# Sleep summary
curl -X POST "https://your-vercel-domain.com/api/withings/sleep" \
  -H "x-medoxie-address: ${ADDRESS}" \
  -H "x-medoxie-profile-id: ${PROFILE_ID}" \
  -H "x-medoxie-timestamp: ${TIMESTAMP}" \
  -H "x-medoxie-message: Medoxie Withings API Access
address: ${ADDRESS}
profileId: ${PROFILE_ID}
timestamp: ${TIMESTAMP}
path: /sleep" \
  -H "x-medoxie-signature: ${SIGNATURE}" \
  -H "Content-Type: application/json" \
  --data '{"startdate":"1706140800","enddate":"1706745600","tokenBundle":{"access_token":"...","refresh_token":"...","expires_at":1706745600000,"scope":"user.sleepevents"}}'

# Measures
curl -X POST "https://your-vercel-domain.com/api/withings/measure" \
  -H "x-medoxie-address: ${ADDRESS}" \
  -H "x-medoxie-profile-id: ${PROFILE_ID}" \
  -H "x-medoxie-timestamp: ${TIMESTAMP}" \
  -H "x-medoxie-message: Medoxie Withings API Access
address: ${ADDRESS}
profileId: ${PROFILE_ID}
timestamp: ${TIMESTAMP}
path: /measure" \
  -H "x-medoxie-signature: ${SIGNATURE}" \
  -H "Content-Type: application/json" \
  --data '{"startdate":"1706140800","enddate":"1706745600","tokenBundle":{"access_token":"...","refresh_token":"...","expires_at":1706745600000,"scope":"user.metrics"}}'

# Activity
curl -X POST "https://your-vercel-domain.com/api/withings/activity" \
  -H "x-medoxie-address: ${ADDRESS}" \
  -H "x-medoxie-profile-id: ${PROFILE_ID}" \
  -H "x-medoxie-timestamp: ${TIMESTAMP}" \
  -H "x-medoxie-message: Medoxie Withings API Access
address: ${ADDRESS}
profileId: ${PROFILE_ID}
timestamp: ${TIMESTAMP}
path: /activity" \
  -H "x-medoxie-signature: ${SIGNATURE}" \
  -H "Content-Type: application/json" \
  --data '{"startdate":"1706140800","enddate":"1706745600","tokenBundle":{"access_token":"...","refresh_token":"...","expires_at":1706745600000,"scope":"user.activity"}}'
```

## Basic integration test approach (pseudocode)

```
1. Call /api/withings/auth/start with valid wallet + profile headers.
2. Open returned url and complete Withings consent.
3. Verify `/api/withings/auth/callback` stores a one-time result, not long-lived tokens.
4. Consume `/api/withings/auth/result` once with the same wallet + profile headers.
5. Call `/api/withings/sleep` with wallet + profile headers, date range, and token bundle body.
6. Expire the client-supplied access token, call again, and verify the response returns a replacement token bundle.
7. Reuse the consumed result id and confirm it fails.
```

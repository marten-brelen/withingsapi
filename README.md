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
- `TOKEN_STORE_TOKEN` (Upstash Redis REST token)

## Endpoints

- `GET /api/health`
- `GET /api/withings/auth/start?user_id=...`
- `GET /api/withings/auth/callback`
- `POST /api/withings/token/refresh?user_id=...`
- `GET /api/withings/sleep?user_id=...&startdate=...&enddate=...`
- `GET /api/withings/measure?user_id=...&startdate=...&enddate=...`
- `GET /api/withings/activity?user_id=...&startdate=...&enddate=...`

## Example curl

```bash
# Health
curl https://your-vercel-domain.com/api/health

# Start OAuth
curl "https://your-vercel-domain.com/api/withings/auth/start?user_id=medoxie-123"

# Refresh token (POST with query param)
curl -X POST "https://your-vercel-domain.com/api/withings/token/refresh?user_id=medoxie-123"

# Sleep summary
curl "https://your-vercel-domain.com/api/withings/sleep?user_id=medoxie-123&startdate=1706140800&enddate=1706745600"

# Measures
curl "https://your-vercel-domain.com/api/withings/measure?user_id=medoxie-123&startdate=1706140800&enddate=1706745600"

# Activity
curl "https://your-vercel-domain.com/api/withings/activity?user_id=medoxie-123&startdate=1706140800&enddate=1706745600"
```

## Basic integration test approach (pseudocode)

```
1. Call /api/withings/auth/start with user_id.
2. Open returned url and complete Withings consent.
3. Verify /api/withings/auth/callback stores tokens (check via Redis).
4. Call /api/withings/sleep with user_id and date range.
5. Expire access token in Redis, call again to verify refresh.
6. Delete tokens, call sleep endpoint and confirm 401 not_connected.
```

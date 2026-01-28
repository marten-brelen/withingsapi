import { getWithingsApiBaseUrl } from "./oauth";

type WithingsResponse<T> = {
  status?: number;
  error?: string;
  message?: string;
  body?: T;
};

export class WithingsError extends Error {
  status: number | null;
  code: string | null;

  constructor(message: string, status?: number, code?: string) {
    super(message);
    this.name = "WithingsError";
    this.status = status ?? null;
    this.code = code ?? null;
  }
}

async function fetchWithings<T>(
  path: string,
  action: string,
  params: Record<string, string>,
  accessToken: string
): Promise<T> {
  const url = new URL(path, getWithingsApiBaseUrl());
  const body = new URLSearchParams({ action, ...params });

  console.log("Withings API request:", {
    url: url.toString(),
    action,
    params: Object.keys(params),
    hasAccessToken: !!accessToken,
  });

  const response = await fetch(url.toString(), {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: body.toString(),
  });

  const data = (await response.json()) as WithingsResponse<T>;

  console.log("Withings API response:", {
    status: data.status,
    error: data.error,
    message: data.message,
    hasBody: !!data.body,
  });

  if (data.status && data.status !== 0) {
    throw new WithingsError(
      data.message || data.error || "Withings API error",
      data.status,
      data.error
    );
  }
  if (!response.ok) {
    throw new WithingsError("Withings API error", response.status);
  }
  if (!data.body) {
    throw new WithingsError("Withings API returned empty body");
  }

  return data.body;
}

export async function getSleepSummary(
  accessToken: string,
  startdate: string,
  enddate: string
): Promise<unknown> {
  return fetchWithings(
    "/v2/sleep",
    "getsummary",
    {
      startdate,
      enddate,
      data_fields:
        "hr,rr,snoring,hrv,breathing_disturbances,deepsleepduration,lightsleepduration,remsleepduration,wakeupduration,sleep_score,sleep_latency,sleep_efficiency",
    },
    accessToken
  );
}

export async function getMeasures(
  accessToken: string,
  startdate: string,
  enddate: string
): Promise<unknown> {
  return fetchWithings(
    "/v2/measure",
    "getmeas",
    { startdate, enddate },
    accessToken
  );
}

export async function getActivity(
  accessToken: string,
  startdate: string,
  enddate: string
): Promise<unknown> {
  return fetchWithings(
    "/v2/measure",
    "getactivity",
    { startdate, enddate },
    accessToken
  );
}

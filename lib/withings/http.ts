import type { VercelRequest, VercelResponse } from "@vercel/node";

export function sendJson(
  res: VercelResponse,
  status: number,
  payload: Record<string, unknown>
): void {
  res.status(status).json(payload);
}

export function sendError(
  res: VercelResponse,
  status: number,
  error: string,
  message: string
): void {
  sendJson(res, status, { error, message });
}

export function requireMethod(
  req: VercelRequest,
  res: VercelResponse,
  method: string
): boolean {
  if (req.method !== method) {
    sendError(res, 405, "method_not_allowed", `Use ${method}`);
    return false;
  }
  return true;
}

export function getRequiredQueryParam(
  req: VercelRequest,
  res: VercelResponse,
  name: string
): string | null {
  const value = req.query[name];
  if (typeof value !== "string" || value.trim().length === 0) {
    sendError(res, 400, "invalid_request", `${name} is required`);
    return null;
  }
  return value.trim();
}

export function getRequiredDateParam(
  req: VercelRequest,
  res: VercelResponse,
  name: string
): string | null {
  const value = getRequiredQueryParam(req, res, name);
  if (!value) {
    return null;
  }
  if (!/^\d+$/.test(value)) {
    sendError(res, 400, "invalid_request", `${name} must be a unix timestamp`);
    return null;
  }
  return value;
}

export function enforceHttps(req: VercelRequest, res: VercelResponse): boolean {
  if (process.env.NODE_ENV !== "production") {
    return true;
  }
  const proto = req.headers["x-forwarded-proto"];
  if (proto !== "https") {
    sendError(res, 400, "https_required", "HTTPS is required");
    return false;
  }
  return true;
}

export function rejectLargeBody(
  req: VercelRequest,
  res: VercelResponse,
  maxBytes: number
): boolean {
  const lengthHeader = req.headers["content-length"];
  if (lengthHeader) {
    const length = Number(lengthHeader);
    if (Number.isFinite(length) && length > maxBytes) {
      sendError(res, 413, "payload_too_large", "Request body too large");
      return false;
    }
  }
  return true;
}

export async function parseJsonBody(
  req: VercelRequest
): Promise<Record<string, unknown> | null> {
  if (req.body && typeof req.body === "object") {
    return req.body as Record<string, unknown>;
  }
  if (!req.body || typeof req.body === "string") {
    try {
      return JSON.parse(req.body || "{}") as Record<string, unknown>;
    } catch {
      return null;
    }
  }
  return null;
}

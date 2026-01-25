import type { VercelRequest, VercelResponse } from "@vercel/node";
import { sendJson } from "../lib/withings/http";

export default function handler(_: VercelRequest, res: VercelResponse): void {
  sendJson(res, 200, { ok: true });
}

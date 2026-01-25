import { recoverMessageAddress } from "viem";

export interface WithingsAuthHeaders {
  "x-medoxie-address": string;
  "x-medoxie-profile-id": string;
  "x-medoxie-timestamp": string;
  "x-medoxie-message": string;
  "x-medoxie-signature": string;
}

export interface VerifiedAuth {
  address: string;
  profileId: string;
  timestamp: number;
  path: string;
}

type HeaderValue = string | string[] | undefined;
type HeaderRecord = Record<string, HeaderValue>;

const TIMESTAMP_TOLERANCE_MS = 5 * 60 * 1000;

function getHeader(headers: HeaderRecord, name: string): string | undefined {
  const value = headers[name.toLowerCase()];
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}

function buildExpectedMessage(
  address: string,
  profileId: string,
  timestamp: string,
  path: string
): string {
  return [
    "Medoxie Withings API Access",
    `address: ${address}`,
    `profileId: ${profileId}`,
    `timestamp: ${timestamp}`,
    `path: ${path}`,
  ].join("\n");
}

export async function verifyWithingsAuth(
  headers: HeaderRecord,
  expectedPath: string
): Promise<VerifiedAuth> {
  const address = getHeader(headers, "x-medoxie-address");
  const profileId = getHeader(headers, "x-medoxie-profile-id");
  const timestamp = getHeader(headers, "x-medoxie-timestamp");
  const encodedMessage = getHeader(headers, "x-medoxie-message");
  const signature = getHeader(headers, "x-medoxie-signature");

  if (!address || !profileId || !timestamp || !encodedMessage || !signature) {
    throw new Error("missing_auth_headers");
  }

  let message: string;
  try {
    message = Buffer.from(encodedMessage, "base64").toString("utf-8");
  } catch (error) {
    throw new Error("invalid_message_encoding");
  }

  const timestampMs = Number.parseInt(timestamp, 10);
  if (!Number.isFinite(timestampMs)) {
    throw new Error("invalid_timestamp");
  }

  const age = Math.abs(Date.now() - timestampMs);
  if (age > TIMESTAMP_TOLERANCE_MS) {
    throw new Error("timestamp_out_of_range");
  }

  const expectedMessage = buildExpectedMessage(
    address,
    profileId,
    timestamp,
    expectedPath
  );
  if (message !== expectedMessage) {
    throw new Error("message_mismatch");
  }

  if (!signature.startsWith("0x")) {
    throw new Error("invalid_signature_format");
  }

  let recoveredAddress: string;
  try {
    recoveredAddress = await recoverMessageAddress({
      message,
      signature: signature as `0x${string}`,
    });
  } catch (error) {
    throw new Error("invalid_signature");
  }

  if (recoveredAddress.toLowerCase() !== address.toLowerCase()) {
    throw new Error("signature_mismatch");
  }

  return {
    address: recoveredAddress.toLowerCase(),
    profileId: profileId.toLowerCase(),
    timestamp: timestampMs,
    path: expectedPath,
  };
}

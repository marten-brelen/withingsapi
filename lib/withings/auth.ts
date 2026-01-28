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

  console.log("Auth verification started:", {
    hasAddress: !!address,
    hasProfileId: !!profileId,
    hasTimestamp: !!timestamp,
    hasEncodedMessage: !!encodedMessage,
    hasSignature: !!signature,
    expectedPath,
  });

  if (!address || !profileId || !timestamp || !encodedMessage || !signature) {
    const missing = [];
    if (!address) missing.push("x-medoxie-address");
    if (!profileId) missing.push("x-medoxie-profile-id");
    if (!timestamp) missing.push("x-medoxie-timestamp");
    if (!encodedMessage) missing.push("x-medoxie-message");
    if (!signature) missing.push("x-medoxie-signature");
    console.error("Missing auth headers:", missing);
    throw new Error("missing_auth_headers");
  }

  let message: string;
  try {
    message = Buffer.from(encodedMessage, "base64").toString("utf-8");
    console.log("Decoded message length:", message.length);
  } catch (error) {
    console.error("Base64 decode failed:", {
      error: error instanceof Error ? error.message : String(error),
      encodedLength: encodedMessage.length,
    });
    throw new Error("invalid_message_encoding");
  }

  const timestampMs = Number.parseInt(timestamp, 10);
  if (!Number.isFinite(timestampMs)) {
    console.error("Invalid timestamp:", { timestamp, parsed: timestampMs });
    throw new Error("invalid_timestamp");
  }

  const age = Math.abs(Date.now() - timestampMs);
  if (age > TIMESTAMP_TOLERANCE_MS) {
    console.error("Timestamp out of range:", {
      timestamp: timestampMs,
      currentTime: Date.now(),
      ageMs: age,
      toleranceMs: TIMESTAMP_TOLERANCE_MS,
    });
    throw new Error("timestamp_out_of_range");
  }

  // Normalize address and profileId to lowercase for consistent comparison
  const normalizedAddress = address.toLowerCase();
  const normalizedProfileId = profileId.toLowerCase();

  const expectedMessage = buildExpectedMessage(
    normalizedAddress,
    normalizedProfileId,
    timestamp,
    expectedPath
  );

  console.log("Message comparison:", {
    decodedLength: message.length,
    expectedLength: expectedMessage.length,
    decodedPreview: message.substring(0, 100).replace(/\n/g, "\\n"),
    expectedPreview: expectedMessage.substring(0, 100).replace(/\n/g, "\\n"),
    match: message === expectedMessage,
  });

  if (message !== expectedMessage) {
    // Log detailed diff for debugging
    const decodedLines = message.split("\n");
    const expectedLines = expectedMessage.split("\n");
    console.error("Message mismatch:", {
      decodedLines: decodedLines.length,
      expectedLines: expectedLines.length,
      decoded: JSON.stringify(message),
      expected: JSON.stringify(expectedMessage),
      lineByLine: decodedLines.map((line, i) => ({
        line: i,
        decoded: line,
        expected: expectedLines[i],
        match: line === expectedLines[i],
      })),
    });
    throw new Error("message_mismatch");
  }

  if (!signature.startsWith("0x")) {
    console.error("Invalid signature format:", {
      signaturePrefix: signature.substring(0, 10),
    });
    throw new Error("invalid_signature_format");
  }

  let recoveredAddress: string;
  try {
    recoveredAddress = await recoverMessageAddress({
      message,
      signature: signature as `0x${string}`,
    });
    console.log("Signature recovered:", {
      recovered: recoveredAddress.toLowerCase(),
      provided: address.toLowerCase(),
      match: recoveredAddress.toLowerCase() === address.toLowerCase(),
    });
  } catch (error) {
    console.error("Signature recovery failed:", {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    throw new Error("invalid_signature");
  }

  if (recoveredAddress.toLowerCase() !== normalizedAddress) {
    console.error("Signature mismatch:", {
      recovered: recoveredAddress.toLowerCase(),
      provided: normalizedAddress,
    });
    throw new Error("signature_mismatch");
  }

  console.log("Auth verification successful:", {
    address: recoveredAddress.toLowerCase(),
    profileId: normalizedProfileId,
  });

  return {
    address: recoveredAddress.toLowerCase(),
    profileId: normalizedProfileId,
    timestamp: timestampMs,
    path: expectedPath,
  };
}

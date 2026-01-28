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
    console.log("Decoded message:", JSON.stringify(message));
  } catch (error) {
    console.error("Base64 decode failed:", {
      error: error instanceof Error ? error.message : String(error),
      encodedLength: encodedMessage.length,
    });
    throw new Error("invalid_message_encoding");
  }

  // Parse address and profileId from the decoded message
  // Format: "Medoxie Withings API Access\naddress: {address}\nprofileId: {profileId}\ntimestamp: {timestamp}\npath: {path}"
  const messageLines = message.split("\n");
  if (messageLines.length < 5) {
    console.error("Invalid message format - insufficient lines:", {
      lineCount: messageLines.length,
      lines: messageLines,
    });
    throw new Error("invalid_message_format");
  }

  let messageAddress: string | undefined;
  let messageProfileId: string | undefined;
  let messageTimestamp: string | undefined;
  let messagePath: string | undefined;

  for (const line of messageLines) {
    if (line.startsWith("address: ")) {
      messageAddress = line.substring("address: ".length).trim();
    } else if (line.startsWith("profileId: ")) {
      messageProfileId = line.substring("profileId: ".length).trim();
    } else if (line.startsWith("timestamp: ")) {
      messageTimestamp = line.substring("timestamp: ".length).trim();
    } else if (line.startsWith("path: ")) {
      messagePath = line.substring("path: ".length).trim();
    }
  }

  console.log("Parsed message fields:", {
    messageAddress,
    messageProfileId,
    messageTimestamp,
    messagePath,
    headerAddress: address,
    headerProfileId: profileId,
    headerTimestamp: timestamp,
  });

  if (!messageAddress || !messageProfileId || !messageTimestamp || !messagePath) {
    console.error("Missing required fields in message:", {
      hasAddress: !!messageAddress,
      hasProfileId: !!messageProfileId,
      hasTimestamp: !!messageTimestamp,
      hasPath: !!messagePath,
      messageLines,
    });
    throw new Error("invalid_message_format");
  }

  // Normalize values for comparison
  const normalizedHeaderAddress = address.toLowerCase();
  const normalizedHeaderProfileId = profileId.toLowerCase();
  const normalizedMessageAddress = messageAddress.toLowerCase();
  const normalizedMessageProfileId = messageProfileId.toLowerCase();

  // Verify message fields match headers
  if (normalizedMessageAddress !== normalizedHeaderAddress) {
    console.error("Address mismatch between message and header:", {
      messageAddress: normalizedMessageAddress,
      headerAddress: normalizedHeaderAddress,
    });
    throw new Error("address_mismatch");
  }

  if (normalizedMessageProfileId !== normalizedHeaderProfileId) {
    console.error("ProfileId mismatch between message and header:", {
      messageProfileId: normalizedMessageProfileId,
      headerProfileId: normalizedHeaderProfileId,
    });
    throw new Error("profileid_mismatch");
  }

  if (messageTimestamp !== timestamp) {
    console.error("Timestamp mismatch between message and header:", {
      messageTimestamp,
      headerTimestamp: timestamp,
    });
    throw new Error("timestamp_mismatch");
  }

  if (messagePath !== expectedPath) {
    console.error("Path mismatch:", {
      messagePath,
      expectedPath,
    });
    throw new Error("path_mismatch");
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
      messageAddress: normalizedMessageAddress,
      headerAddress: normalizedHeaderAddress,
      match: recoveredAddress.toLowerCase() === normalizedMessageAddress,
    });
  } catch (error) {
    console.error("Signature recovery failed:", {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    throw new Error("invalid_signature");
  }

  // Verify signature recovers to the address in the message (source of truth)
  if (recoveredAddress.toLowerCase() !== normalizedMessageAddress) {
    console.error("Signature mismatch - recovered address doesn't match message address:", {
      recovered: recoveredAddress.toLowerCase(),
      messageAddress: normalizedMessageAddress,
    });
    throw new Error("signature_mismatch");
  }

  console.log("Auth verification successful:", {
    address: recoveredAddress.toLowerCase(),
    profileId: normalizedMessageProfileId,
  });

  return {
    address: recoveredAddress.toLowerCase(),
    profileId: normalizedMessageProfileId,
    timestamp: timestampMs,
    path: expectedPath,
  };
}

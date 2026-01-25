import { fetchAccount } from "@lens-protocol/client/actions";
import { evmAddress } from "@lens-protocol/client";
import { lensClient } from "./lensClient";

export async function verifyLensProfileOwnership(
  walletAddress: string,
  profileId: string
): Promise<boolean> {
  try {
    const accountResult = await fetchAccount(lensClient, {
      address: evmAddress(profileId),
    });

    if (accountResult.isErr() || !accountResult.value) {
      return false;
    }

    const account = accountResult.value as {
      account?: { address?: string };
      address?: string;
      ownedBy?: { address?: string } | string;
    };

    const ownerCandidate =
      account.account?.address ||
      account.ownedBy?.address ||
      (typeof account.ownedBy === "string" ? account.ownedBy : undefined) ||
      account.address;

    if (!ownerCandidate) {
      return false;
    }

    return ownerCandidate.toLowerCase() === walletAddress.toLowerCase();
  } catch {
    return false;
  }
}

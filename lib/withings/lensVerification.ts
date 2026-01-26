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

    const account = accountResult.value as { address?: string };
    if (!account.address) {
      return false;
    }

    return account.address.toLowerCase() === walletAddress.toLowerCase();
  } catch {
    return false;
  }
}

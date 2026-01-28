import { fetchAccount } from "@lens-protocol/client/actions";
import { evmAddress } from "@lens-protocol/client";
import { lensClient } from "./lensClient";

export async function verifyLensProfileOwnership(
  walletAddress: string,
  profileId: string
): Promise<boolean> {
  try {
    console.log("Fetching Lens account:", {
      profileId,
      walletAddress,
      usingEvmAddress: evmAddress(profileId),
    });

    const accountResult = await fetchAccount(lensClient, {
      address: evmAddress(profileId),
    });

    console.log("Lens account fetch result:", {
      isErr: accountResult.isErr(),
      hasValue: !!accountResult.value,
      error: accountResult.isErr() ? accountResult.error : undefined,
    });

    if (accountResult.isErr() || !accountResult.value) {
      console.warn("Lens account not found or error:", {
        profileId,
        error: accountResult.isErr() ? accountResult.error : "no value",
      });
      return false;
    }

    const account = accountResult.value as { address?: string };
    console.log("Lens account data:", {
      accountAddress: account.address,
      walletAddress,
      match: account.address?.toLowerCase() === walletAddress.toLowerCase(),
    });

    if (!account.address) {
      console.warn("Lens account has no address:", { profileId });
      return false;
    }

    const matches = account.address.toLowerCase() === walletAddress.toLowerCase();
    console.log("Lens ownership check:", {
      profileId,
      accountAddress: account.address.toLowerCase(),
      walletAddress: walletAddress.toLowerCase(),
      matches,
    });

    return matches;
  } catch (error) {
    console.error("Lens verification exception:", {
      profileId,
      walletAddress,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    return false;
  }
}

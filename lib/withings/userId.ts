import { fetchAccount } from "@lens-protocol/client/actions";
import { evmAddress } from "@lens-protocol/client";
import { lensClient } from "./lensClient";

type LensAttribute = {
  key?: string;
  value?: string;
};

export async function resolveUserIdFromProfile(
  profileId: string
): Promise<string | null> {
  try {
    const accountResult = await fetchAccount(lensClient, {
      address: evmAddress(profileId),
    });

    if (accountResult.isErr() || !accountResult.value) {
      return null;
    }

    const account = accountResult.value as {
      metadata?: { attributes?: LensAttribute[] };
    };
    const attributes = account.metadata?.attributes || [];
    const emailAttr = attributes.find(
      (attr) =>
        attr.key === "WithingsEmail" ||
        attr.key === "Withings" ||
        attr.key === "Email" ||
        attr.key === "email"
    );

    if (emailAttr?.value) {
      return emailAttr.value;
    }

    return null;
  } catch {
    return null;
  }
}

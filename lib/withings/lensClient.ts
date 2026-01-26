import { PublicClient, mainnet, testnet } from "@lens-protocol/client";

const environment =
  process.env.LENS_ENVIRONMENT === "development" ? testnet : mainnet;

export const lensClient = PublicClient.create({
  environment,
  fragments: [],
});

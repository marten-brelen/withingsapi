import { LensClient, production, development } from "@lens-protocol/client";

const environment =
  process.env.LENS_ENVIRONMENT === "development" ? development : production;

export const lensClient = new LensClient({
  environment,
});

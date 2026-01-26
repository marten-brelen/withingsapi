export async function resolveUserIdFromProfile(
  profileId: string
): Promise<string | null> {
  return profileId.toLowerCase();
}

/**
 * Repo-relative path helpers shared by every extractor, so that W6 and W8 cannot
 * each reinvent them with different spellings for the repo root (A2 F10).
 */

/**
 * POSIX dirname of a repo-relative path, with the repo root spelled `""`.
 *
 * Never `"."`, never `"/"`, never a trailing slash. The empty string is a valid
 * scope and is NOT `null`: callers gating on a scope must test `!== null`, never
 * truthiness.
 */
export function parentScope(path: string): string {
  const index = path.lastIndexOf("/");
  return index <= 0 ? "" : path.slice(0, index);
}

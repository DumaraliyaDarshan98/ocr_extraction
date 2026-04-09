import { compareTwoStrings } from "string-similarity";

/**
 * Returns a 0–100 similarity score (Dice coefficient) between two names.
 */
export function computeNameMatchScorePercent(
  extractedName: string,
  expectedName: string
): number {
  const a = extractedName.trim().toLowerCase();
  const b = expectedName.trim().toLowerCase();
  if (!a && !b) {
    return 100;
  }
  if (!a || !b) {
    return 0;
  }
  return Math.round(compareTwoStrings(a, b) * 100);
}

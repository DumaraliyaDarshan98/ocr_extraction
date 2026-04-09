import "dotenv/config";

export interface KycThresholds {
  nameMatchPercent: number;
  minAge: number;
  fieldConfidence: number;
  faceMatchScore: number;
  /** Euclidean distance normalization divisor (same-person distances are often below ~0.55). */
  faceDistanceMax: number;
  nameFieldKeys: string[];
  dobFieldKeys: string[];
}

function num(env: string | undefined, fallback: number): number {
  if (env === undefined || env === "") {
    return fallback;
  }
  const n = Number(env);
  return Number.isFinite(n) ? n : fallback;
}

function list(env: string | undefined, fallback: string): string[] {
  return (env && env.trim() !== "" ? env : fallback)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Thresholds and field keys from environment (no hardcoded business rules in services).
 */
export function getKycThresholds(): KycThresholds {
  return {
    nameMatchPercent: num(process.env.NAME_MATCH_THRESHOLD, 70),
    minAge: num(process.env.MIN_AGE, 18),
    fieldConfidence: num(process.env.FIELD_CONFIDENCE_THRESHOLD, 0.7),
    faceMatchScore: num(process.env.FACE_MATCH_THRESHOLD, 0.7),
    faceDistanceMax: num(process.env.FACE_DISTANCE_MAX, 0.55),
    nameFieldKeys: list(process.env.NAME_FIELD_KEYS, "name,fullName,full_name,holderName"),
    dobFieldKeys: list(process.env.DOB_FIELD_KEYS, "dob,dateOfBirth,birthDate"),
  };
}

export function isFaceMatchEnabled(): boolean {
  const v = (process.env.FACE_MATCH_ENABLED ?? "true").toLowerCase();
  return v !== "false" && v !== "0";
}

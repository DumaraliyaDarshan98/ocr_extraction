const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

function ageOnUtcDate(birthUtc: Date, ref: Date): number {
  let age = ref.getUTCFullYear() - birthUtc.getUTCFullYear();
  const m = ref.getUTCMonth() - birthUtc.getUTCMonth();
  if (m < 0 || (m === 0 && ref.getUTCDate() < birthUtc.getUTCDate())) {
    age -= 1;
  }
  return age;
}

/**
 * Validates `YYYY-MM-DD` and checks age >= minAge (evaluated in UTC).
 */
export function validateDobIso(
  dobRaw: string,
  minAge: number
): { valid: boolean; error?: string } {
  const dob = dobRaw.trim();
  if (!ISO_DATE.test(dob)) {
    return { valid: false, error: "DOB must be YYYY-MM-DD" };
  }

  const birth = new Date(`${dob}T00:00:00.000Z`);
  if (Number.isNaN(birth.getTime())) {
    return { valid: false, error: "Invalid date" };
  }

  const now = new Date();
  if (birth > now) {
    return { valid: false, error: "DOB cannot be in the future" };
  }

  const age = ageOnUtcDate(birth, now);
  if (age < minAge) {
    return { valid: false, error: `Age must be at least ${minAge}` };
  }

  return { valid: true };
}

export const validateAadhaar = (text: string) => {

  const regex = /\b\d{4}\s?\d{4}\s?\d{4}\b/;

  const match = text.match(regex);

  if (!match) {
    return { valid: false };
  }

  const number = match[0].replace(/\s/g, "");

  const valid = validateVerhoeff(number);

  return {
    number,
    valid
  };
};

/**
 * Verhoeff checksum implementation for Aadhaar validation.
 * See: https://en.wikipedia.org/wiki/Verhoeff_algorithm
 */
const d: number[][] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const p: number[][] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

const inv: number[] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

const validateVerhoeff = (num: string): boolean => {
  if (!/^\d+$/.test(num)) return false;

  let c = 0;
  const digits: number[] = num.split("").reverse().map((d) => parseInt(d, 10));

  for (let i = 0; i < digits.length; i++) {
    const digit = digits[i] as number;
    // Guard against unexpected values to satisfy TypeScript and keep runtime safe
    if (digit < 0 || digit > 9) {
      return false;
    }
    const rowIndex = (i + 1) % 8;
    const permutationRow = p[rowIndex];
    if (!permutationRow) {
      return false;
    }
    const next = permutationRow[digit];
    if (next === undefined) {
      return false;
    }
    const dRow = d[c];
    if (!dRow) {
      return false;
    }
    const newC = dRow[next];
    if (newC === undefined) {
      return false;
    }
    c = newC;
  }

  return c === 0;
};
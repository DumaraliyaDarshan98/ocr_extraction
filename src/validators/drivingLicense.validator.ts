export const validateDrivingLicense = (text: string) => {
  // Common Indian driving license pattern examples:
  // - KA01 20110012345
  // - MH12 20110012345
  const regex = /\b[A-Z]{2}\d{2}\s?\d{11}\b/;

  const match = text.match(regex);

  if (!match) {
    return { valid: false };
  }

  return {
    number: match[0],
    valid: true,
  };
};

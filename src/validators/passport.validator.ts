export const validatePassport = (text: string) => {
  const regex = /\b[A-Z][0-9]{7}\b/;

  const match = text.match(regex);

  if (!match) {
    return { valid: false };
  }

  return {
    number: match[0],
    valid: true,
  };
};

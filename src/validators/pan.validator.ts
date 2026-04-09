export const validatePAN = (text: string) => {

    const regex = /[A-Z]{5}[0-9]{4}[A-Z]{1}/;
  
    const match = text.match(regex);
  
    if (!match) {
      return { valid: false };
    }
  
    return {
      number: match[0],
      valid: true
    };
  };
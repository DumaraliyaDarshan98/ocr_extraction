import Tesseract from "tesseract.js";

export const extractText = async (
  filePath: string,
  mimeType?: string
): Promise<string> => {
  const normalizedMime = String(mimeType ?? "").toLowerCase();
  if (normalizedMime === "application/pdf") {
    return "";
  }
  try {
    const result = await Tesseract.recognize(filePath, "eng");
    return result.data.text.toLowerCase();
  } catch {
    return "";
  }
};
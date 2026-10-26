import Tesseract from "tesseract.js";
import fs from "fs";

/**
 * Extract text from an image (Tesseract) or PDF (text-layer parse fallback).
 * PDFs without an embedded text layer still rely on Gemini upstream.
 */
export const extractText = async (
  filePath: string,
  mimeType?: string
): Promise<string> => {
  const normalizedMime = String(mimeType ?? "").toLowerCase();

  if (normalizedMime === "application/pdf" || filePath.toLowerCase().endsWith(".pdf")) {
    return extractPdfText(filePath);
  }

  try {
    const result = await Tesseract.recognize(filePath, "eng");
    return (result.data.text || "").toLowerCase();
  } catch {
    return "";
  }
};

async function extractPdfText(filePath: string): Promise<string> {
  try {
    // Lightweight PDF text-layer extraction without native deps.
    // Scanned image-only PDFs will still return empty (Gemini handles those).
    const buffer = fs.readFileSync(filePath);
    const raw = buffer.toString("latin1");
    const chunks: string[] = [];
    const streamRegex = /stream([\s\S]*?)endstream/g;
    let match: RegExpExecArray | null;
    while ((match = streamRegex.exec(raw)) !== null) {
      const body = match[1] || "";
      // Prefer uncompressed / Flate-decoded-looking printable runs
      const printable = body.replace(/[^\x20-\x7E\n\r\t]/g, " ");
      if (printable.trim().length > 20) chunks.push(printable);
    }
    // Also pull literal strings from PDF content: (Hello World)
    const literalRegex = /\((?:\\.|[^\\)]){3,}\)/g;
    const literals = raw.match(literalRegex) || [];
    for (const lit of literals.slice(0, 400)) {
      chunks.push(
        lit
          .slice(1, -1)
          .replace(/\\n/g, "\n")
          .replace(/\\r/g, "")
          .replace(/\\t/g, " ")
          .replace(/\\\(/g, "(")
          .replace(/\\\)/g, ")")
          .replace(/\\\\/g, "\\"),
      );
    }
    const text = chunks.join("\n").replace(/\s+/g, " ").trim();
    return text.toLowerCase();
  } catch {
    return "";
  }
}

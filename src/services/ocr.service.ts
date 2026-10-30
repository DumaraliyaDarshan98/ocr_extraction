import Tesseract from "tesseract.js";
import fs from "fs";

/**
 * Extract text from an image (Tesseract) or PDF (pdf-parse v2 + safe fallback).
 * Scanned image-only PDFs may return empty here — Gemini vision handles those upstream.
 */
export const extractText = async (
  filePath: string,
  mimeType?: string,
): Promise<string> => {
  const normalizedMime = String(mimeType ?? "").toLowerCase();

  if (
    normalizedMime === "application/pdf" ||
    filePath.toLowerCase().endsWith(".pdf")
  ) {
    return extractPdfText(filePath);
  }

  try {
    const result = await Tesseract.recognize(filePath, "eng");
    return (result.data.text || "").toLowerCase();
  } catch {
    return "";
  }
};

/**
 * pdf-parse v2 exports `{ PDFParse }` (class), not a callable default function.
 * Calling `require("pdf-parse")(buffer)` throws "pdfParse is not a function".
 */
async function extractWithPdfParse(buffer: Buffer): Promise<string> {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const mod = require("pdf-parse");
  const PDFParse = mod?.PDFParse ?? mod?.default?.PDFParse;

  // Legacy v1 callable API (if ever downgraded)
  if (typeof mod === "function") {
    const parsed = await mod(buffer);
    return String(parsed?.text || "").replace(/\s+/g, " ").trim();
  }
  if (typeof mod?.default === "function") {
    const parsed = await mod.default(buffer);
    return String(parsed?.text || "").replace(/\s+/g, " ").trim();
  }

  if (!PDFParse) {
    throw new Error("pdf-parse PDFParse class not found");
  }

  const parser = new PDFParse({ data: buffer });
  try {
    const result = await parser.getText();
    return String(result?.text || "").replace(/\s+/g, " ").trim();
  } finally {
    try {
      await parser.destroy();
    } catch {
      /* ignore */
    }
  }
}

/** Reject binary/stream garbage that falsely triggers Aadhaar/PAN keyword scorers. */
function isPlausibleOcrText(text: string): boolean {
  const t = (text || "").trim();
  if (t.length < 20) return false;
  if (t.length > 80_000) return false; // binary dump from stream scrape
  const letters = (t.match(/[a-zA-Z]/g) || []).length;
  const digits = (t.match(/\d/g) || []).length;
  const ratio = letters / Math.max(1, t.length);
  // Real KYC PDFs are mostly letters/spaces; stream dumps are noise.
  if (ratio < 0.35) return false;
  if (letters + digits < 30) return false;
  return true;
}

async function extractPdfText(filePath: string): Promise<string> {
  // 1) Prefer pdf-parse v2 text layer (accurate for digital PDFs like Udyam certificates)
  try {
    const buffer = fs.readFileSync(filePath);
    const text = await extractWithPdfParse(buffer);
    if (isPlausibleOcrText(text)) {
      console.log(
        `[OCR:PDF] pdf-parse extracted ${text.length} chars from ${filePath}`,
      );
      return text.toLowerCase();
    }
    console.warn(
      `[OCR:PDF] pdf-parse returned empty/implausible text (${text.length} chars) — trying safe fallback`,
    );
  } catch (err) {
    console.warn("[OCR:PDF] pdf-parse unavailable/failed, using fallback", err);
  }

  // 2) Conservative literal-only fallback (NO raw stream body — that caused ~300k binary chars
  //    and false Aadhaar classifications). Prefer empty → Gemini vision over garbage text.
  try {
    const buffer = fs.readFileSync(filePath);
    const raw = buffer.toString("latin1");
    const chunks: string[] = [];
    const literalRegex = /\((?:\\.|[^\\)]){4,}\)/g;
    const literals = raw.match(literalRegex) || [];
    for (const lit of literals.slice(0, 800)) {
      const decoded = lit
        .slice(1, -1)
        .replace(/\\n/g, "\n")
        .replace(/\\r/g, "")
        .replace(/\\t/g, " ")
        .replace(/\\\(/g, "(")
        .replace(/\\\)/g, ")")
        .replace(/\\\\/g, "\\");
      if (/[A-Za-z]{3,}/.test(decoded)) chunks.push(decoded);
    }
    const text = chunks.join(" ").replace(/\s+/g, " ").trim();
    if (isPlausibleOcrText(text)) {
      console.log(
        `[OCR:PDF] safe-fallback extracted ${text.length} chars from ${filePath}`,
      );
      return text.toLowerCase();
    }
    console.warn(
      `[OCR:PDF] no reliable text layer for ${filePath} — returning empty (Gemini vision will classify)`,
    );
    return "";
  } catch {
    return "";
  }
}

import crypto from "crypto";
import fs from "fs";
import path from "path";

export type FileIntegrityResult = {
  sha256: string;
  sizeBytes: number;
  mimeHint: string | null;
  extension: string;
  magic: string | null;
  formatMismatch: boolean;
  signals: ForensicSignal[];
};

export type ForensicSignal = {
  code: string;
  threatCode: string;
  severity: "low" | "medium" | "high";
  score: number;
  status: "passed" | "failed" | "info" | "skipped";
  title: string;
  description: string;
  evidence?: Record<string, unknown>;
};

function detectMagic(buf: Buffer): string | null {
  if (buf.length >= 5 && buf.subarray(0, 5).toString("ascii") === "%PDF-") return "pdf";
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "jpeg";
  if (
    buf.length >= 8 &&
    buf[0] === 0x89 &&
    buf[1] === 0x50 &&
    buf[2] === 0x4e &&
    buf[3] === 0x47
  ) {
    return "png";
  }
  if (
    buf.length >= 12 &&
    buf.subarray(0, 4).toString("ascii") === "RIFF" &&
    buf.subarray(8, 12).toString("ascii") === "WEBP"
  ) {
    return "webp";
  }
  return null;
}

function normalizeExt(filePath: string): string {
  return path.extname(filePath).replace(".", "").toLowerCase();
}

function expectedMagicForExt(ext: string): string | null {
  if (ext === "pdf") return "pdf";
  if (ext === "jpg" || ext === "jpeg" || ext === "jfif") return "jpeg";
  if (ext === "png") return "png";
  if (ext === "webp") return "webp";
  return null;
}

/**
 * SHA-256 + basic file identity (does not mutate the original file).
 * `originalFileName` is preferred for extension checks (temp upload paths often lack an extension).
 */
export function analyzeFileIntegrity(
  filePath: string,
  mimeTypeHint?: string,
  originalFileName?: string
): FileIntegrityResult {
  const buffer = fs.readFileSync(filePath);
  const sha256 = crypto.createHash("sha256").update(new Uint8Array(buffer)).digest("hex");
  const extension =
    normalizeExt(originalFileName || "") ||
    normalizeExt(filePath) ||
    mimeExtHint(mimeTypeHint);
  const magic = detectMagic(buffer);
  const expected = expectedMagicForExt(extension);
  const signals: ForensicSignal[] = [];

  let formatMismatch = false;
  if (expected && magic && expected !== magic) {
    formatMismatch = true;
    signals.push({
      code: "FILE_FORMAT_MISMATCH",
      threatCode: "T001",
      severity: "high",
      score: 25,
      status: "failed",
      title: "File format mismatch",
      description: `Extension ".${extension}" does not match detected format "${magic}".`,
      evidence: { extension, magic, mimeTypeHint: mimeTypeHint ?? null },
    });
  } else if (expected && !magic) {
    signals.push({
      code: "FILE_SIGNATURE_UNKNOWN",
      threatCode: "T002",
      severity: "medium",
      score: 12,
      status: "failed",
      title: "Unrecognized file signature",
      description: `Could not confirm file magic bytes for ".${extension}".`,
      evidence: { extension, mimeTypeHint: mimeTypeHint ?? null },
    });
  } else {
    signals.push({
      code: "FILE_INTEGRITY_OK",
      threatCode: "T001",
      severity: "low",
      score: 0,
      status: "passed",
      title: "File integrity",
      description: "SHA-256 computed; format signature looks consistent.",
      evidence: { sha256, magic, extension },
    });
  }

  return {
    sha256,
    sizeBytes: buffer.length,
    mimeHint: mimeTypeHint ?? null,
    extension,
    magic,
    formatMismatch,
    signals,
  };
}

function mimeExtHint(mimeTypeHint?: string): string {
  const mime = (mimeTypeHint || "").toLowerCase();
  if (mime.includes("jpeg") || mime.includes("jpg")) return "jpg";
  if (mime.includes("png")) return "png";
  if (mime.includes("webp")) return "webp";
  if (mime.includes("pdf")) return "pdf";
  if (mime.includes("gif")) return "gif";
  return "";
}

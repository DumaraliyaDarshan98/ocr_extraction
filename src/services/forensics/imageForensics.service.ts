import type { ForensicSignal } from "./fileIntegrity.service";
import fs from "fs";
import path from "path";
import crypto from "crypto";

function detectImageMagic(buf: Buffer): string | null {
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
  if (buf.length >= 6 && (buf.subarray(0, 6).toString("ascii") === "GIF87a" || buf.subarray(0, 6).toString("ascii") === "GIF89a")) {
    return "gif";
  }
  if (buf.length >= 2 && buf[0] === 0x42 && buf[1] === 0x4d) return "bmp";
  if (
    buf.length >= 4 &&
    ((buf[0] === 0x49 && buf[1] === 0x49 && buf[2] === 0x2a && buf[3] === 0x00) ||
      (buf[0] === 0x4d && buf[1] === 0x4d && buf[2] === 0x00 && buf[3] === 0x2a))
  ) {
    return "tiff";
  }
  return null;
}

/**
 * Extra image-category signals (all common image types).
 * Core format integrity still comes from analyzeFileIntegrity.
 */
export function analyzeImageForensics(
  filePath: string,
  originalFileName?: string,
  mimeTypeHint?: string
): ForensicSignal[] {
  const buffer = fs.readFileSync(filePath);
  const ext =
    path.extname(originalFileName || "").replace(".", "").toLowerCase() ||
    path.extname(filePath).replace(".", "").toLowerCase() ||
    mimeToExt(mimeTypeHint);
  const magic = detectImageMagic(buffer);
  const signals: ForensicSignal[] = [];

  if (magic) {
    signals.push({
      code: "IMAGE_TYPE_RECORDED",
      threatCode: "T011",
      severity: "low",
      score: 0,
      status: "info",
      title: "Image type recorded",
      description: `Detected image type "${magic}" (extension ".${ext || "unknown"}").`,
      evidence: { magic, extension: ext, sizeBytes: buffer.length },
    });
  }

  if (buffer.length > 0 && buffer.length < 512) {
    signals.push({
      code: "IMAGE_EMPTY_OR_TINY",
      threatCode: "T012",
      severity: "medium",
      score: 10,
      status: "failed",
      title: "Image file too small",
      description: `Image is only ${buffer.length} bytes — may be incomplete or placeholder.`,
      evidence: { sizeBytes: buffer.length },
    });
  }

  const sha256 = crypto.createHash("sha256").update(new Uint8Array(buffer)).digest("hex");
  if (!signals.some((s) => s.code === "IMAGE_TYPE_RECORDED") && !magic) {
    signals.push({
      code: "IMAGE_TYPE_RECORDED",
      threatCode: "T011",
      severity: "low",
      score: 0,
      status: "info",
      title: "Image type recorded",
      description: `Could not classify image magic; sha256=${sha256.slice(0, 12)}…`,
      evidence: { sha256, extension: ext, sizeBytes: buffer.length },
    });
  }

  return signals;
}

function mimeToExt(mimeTypeHint?: string): string {
  const mime = (mimeTypeHint || "").toLowerCase();
  if (mime.includes("jpeg") || mime.includes("jpg")) return "jpg";
  if (mime.includes("png")) return "png";
  if (mime.includes("webp")) return "webp";
  if (mime.includes("gif")) return "gif";
  if (mime.includes("bmp")) return "bmp";
  if (mime.includes("tiff")) return "tiff";
  return "";
}

import type { ForensicSignal } from "./fileIntegrity.service";
import fs from "fs";
import path from "path";
import crypto from "crypto";

function isZipMagic(buf: Buffer): boolean {
  return (
    buf.length >= 4 &&
    buf[0] === 0x50 &&
    buf[1] === 0x4b &&
    (buf[2] === 0x03 || buf[2] === 0x05 || buf[2] === 0x07)
  );
}

/** Count ZIP local-file headers (PK\\x03\\x04) without full unzip. */
function countZipLocalHeaders(buf: Buffer): number {
  let count = 0;
  for (let i = 0; i < buf.length - 3; i++) {
    if (buf[i] === 0x50 && buf[i + 1] === 0x4b && buf[i + 2] === 0x03 && buf[i + 3] === 0x04) {
      count++;
      // skip ahead a bit to avoid dense false positives in compressed streams
      i += 30;
    }
    if (count > 5000) break;
  }
  return count;
}

export function analyzeZipForensics(filePath: string): {
  sha256: string;
  sizeBytes: number;
  signals: ForensicSignal[];
} {
  const buffer = fs.readFileSync(filePath);
  const sha256 = crypto.createHash("sha256").update(new Uint8Array(buffer)).digest("hex");
  const ext = path.extname(filePath).replace(".", "").toLowerCase();
  const zipOk = isZipMagic(buffer);
  const signals: ForensicSignal[] = [];

  if (["zip", "docx", "xlsx", "pptx"].includes(ext) || ext === "zip") {
    // pure zip category uploads
  }

  if (ext === "zip" || ext === "jar" || !ext) {
    if (!zipOk) {
      signals.push({
        code: "ZIP_FORMAT_MISMATCH",
        threatCode: "T031",
        severity: "high",
        score: 25,
        status: "failed",
        title: "Archive format mismatch",
        description: `Extension ".${ext || "unknown"}" does not match ZIP magic bytes.`,
        evidence: { extension: ext },
      });
    } else {
      signals.push({
        code: "ZIP_INTEGRITY_OK",
        threatCode: "T031",
        severity: "low",
        score: 0,
        status: "passed",
        title: "Archive integrity",
        description: "SHA-256 computed; ZIP signature looks consistent.",
        evidence: { sha256, extension: ext },
      });
    }
  } else if (!zipOk && ["zip", "rar", "7z"].includes(ext)) {
    signals.push({
      code: "ZIP_SIGNATURE_UNKNOWN",
      threatCode: "T032",
      severity: "medium",
      score: 12,
      status: "failed",
      title: "Unrecognized archive signature",
      description: `Could not confirm archive magic for ".${ext}".`,
      evidence: { extension: ext },
    });
  } else if (zipOk) {
    signals.push({
      code: "ZIP_INTEGRITY_OK",
      threatCode: "T031",
      severity: "low",
      score: 0,
      status: "passed",
      title: "Archive integrity",
      description: "SHA-256 computed; ZIP signature looks consistent.",
      evidence: { sha256, extension: ext },
    });
  } else {
    signals.push({
      code: "ZIP_SIGNATURE_UNKNOWN",
      threatCode: "T032",
      severity: "medium",
      score: 12,
      status: "failed",
      title: "Unrecognized archive signature",
      description: `Could not confirm archive magic for ".${ext || "unknown"}".`,
      evidence: { extension: ext },
    });
  }

  if (zipOk) {
    const entries = countZipLocalHeaders(buffer);
    if (entries === 0) {
      signals.push({
        code: "ZIP_EMPTY_ARCHIVE",
        threatCode: "T033",
        severity: "medium",
        score: 14,
        status: "failed",
        title: "Empty archive",
        description: "No ZIP local file headers found — archive may be empty or truncated.",
        evidence: { entries },
      });
    } else {
      signals.push({
        code: "ZIP_ENTRY_COUNT_RECORDED",
        threatCode: "T034",
        severity: "low",
        score: 0,
        status: "info",
        title: "Archive entry count recorded",
        description: `Detected about ${entries} local file header(s) in the archive.`,
        evidence: { entries },
      });
    }
  }

  return { sha256, sizeBytes: buffer.length, signals };
}

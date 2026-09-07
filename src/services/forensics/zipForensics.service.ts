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
      i += 30;
    }
    if (count > 5000) break;
  }
  return count;
}

const SUSPICIOUS_EXTS = new Set([
  "exe",
  "dll",
  "bat",
  "cmd",
  "ps1",
  "vbs",
  "js",
  "jse",
  "wsf",
  "scr",
  "msi",
  "com",
  "jar",
]);

/** Extract uncompressed file names from local headers (best-effort). */
function listZipNames(buf: Buffer, max = 200): string[] {
  const names: string[] = [];
  let i = 0;
  while (i < buf.length - 30 && names.length < max) {
    if (buf[i] !== 0x50 || buf[i + 1] !== 0x4b || buf[i + 2] !== 0x03 || buf[i + 3] !== 0x04) {
      i++;
      continue;
    }
    const compSize = buf.readUInt32LE(i + 18);
    const nameLen = buf.readUInt16LE(i + 26);
    const extraLen = buf.readUInt16LE(i + 28);
    const name = buf.subarray(i + 30, i + 30 + nameLen).toString("utf8");
    if (name) names.push(name.replace(/\\/g, "/"));
    i = i + 30 + nameLen + extraLen + compSize;
  }
  return names;
}

export function analyzeZipForensics(
  filePath: string,
  originalFileName?: string
): {
  sha256: string;
  sizeBytes: number;
  signals: ForensicSignal[];
} {
  const buffer = fs.readFileSync(filePath);
  const sha256 = crypto.createHash("sha256").update(new Uint8Array(buffer)).digest("hex");
  const ext =
    path.extname(originalFileName || "").replace(".", "").toLowerCase() ||
    path.extname(filePath).replace(".", "").toLowerCase();
  const zipOk = isZipMagic(buffer);
  const signals: ForensicSignal[] = [];

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

    const names = listZipNames(buffer);
    const suspicious = names.filter((n) => {
      const base = n.split("/").pop() || n;
      const parts = base.toLowerCase().split(".");
      if (parts.length < 2) return false;
      const last = parts[parts.length - 1] || "";
      if (SUSPICIOUS_EXTS.has(last)) return true;
      return false;
    });

    if (suspicious.length) {
      signals.push({
        code: "ZIP_SUSPICIOUS_ENTRIES",
        threatCode: "T035",
        severity: "high",
        score: 28,
        status: "failed",
        title: "Suspicious files inside archive",
        description: `Archive contains risky payloads: ${suspicious.slice(0, 5).join(", ")}${
          suspicious.length > 5 ? "…" : ""
        }.`,
        evidence: { suspicious: suspicious.slice(0, 20) },
      });
    } else if (names.length) {
      signals.push({
        code: "ZIP_ENTRIES_CLEAN",
        threatCode: "T035",
        severity: "low",
        score: 0,
        status: "passed",
        title: "Archive entries look clean",
        description: `No executable / script extensions among ${names.length} listed names.`,
      });
    }

    // Nested document images that look like re-packaged edited scans
    const nestedDocs = names.filter((n) =>
      /\.(pdf|jpe?g|png|webp|docx?|xlsx?)$/i.test(n)
    );
    if (nestedDocs.length >= 1) {
      signals.push({
        code: "ZIP_NESTED_DOCUMENTS",
        threatCode: "T036",
        severity: "low",
        score: 0,
        status: "info",
        title: "Nested documents in archive",
        description: `Archive includes ${nestedDocs.length} document/image file(s). Inner files should be verified individually after extract.`,
        evidence: { nested: nestedDocs.slice(0, 15) },
      });
    }
  }

  return { sha256, sizeBytes: buffer.length, signals };
}

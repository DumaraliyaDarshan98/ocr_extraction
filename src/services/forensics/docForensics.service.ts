import type { ForensicSignal } from "./fileIntegrity.service";
import fs from "fs";
import path from "path";
import crypto from "crypto";

function detectDocMagic(buf: Buffer): string | null {
  // OLE Compound File (legacy .doc/.xls/.ppt)
  if (
    buf.length >= 8 &&
    buf[0] === 0xd0 &&
    buf[1] === 0xcf &&
    buf[2] === 0x11 &&
    buf[3] === 0xe0
  ) {
    return "ole";
  }
  // OOXML (docx/xlsx/pptx) is a ZIP container
  if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && (buf[2] === 0x03 || buf[2] === 0x05 || buf[2] === 0x07)) {
    return "ooxml";
  }
  // RTF
  if (buf.length >= 5 && buf.subarray(0, 5).toString("ascii") === "{\\rtf") return "rtf";
  // ODF also ZIP-based — treat as ooxml-like container
  return null;
}

function expectedDocMagic(ext: string): string | null {
  if (["doc", "xls", "ppt"].includes(ext)) return "ole";
  if (["docx", "xlsx", "pptx", "odt", "ods", "odp"].includes(ext)) return "ooxml";
  if (ext === "rtf") return "rtf";
  return null;
}

export function analyzeDocForensics(filePath: string): {
  sha256: string;
  sizeBytes: number;
  signals: ForensicSignal[];
} {
  const buffer = fs.readFileSync(filePath);
  const sha256 = crypto.createHash("sha256").update(new Uint8Array(buffer)).digest("hex");
  const ext = path.extname(filePath).replace(".", "").toLowerCase();
  const magic = detectDocMagic(buffer);
  const expected = expectedDocMagic(ext);
  const signals: ForensicSignal[] = [];

  if (expected && magic && expected !== magic) {
    signals.push({
      code: "DOC_FORMAT_MISMATCH",
      threatCode: "T021",
      severity: "high",
      score: 25,
      status: "failed",
      title: "Document format mismatch",
      description: `Extension ".${ext}" expects "${expected}" but detected "${magic}".`,
      evidence: { extension: ext, magic, expected },
    });
  } else if (expected && !magic) {
    signals.push({
      code: "DOC_SIGNATURE_UNKNOWN",
      threatCode: "T022",
      severity: "medium",
      score: 12,
      status: "failed",
      title: "Unrecognized document signature",
      description: `Could not confirm office-document magic bytes for ".${ext}".`,
      evidence: { extension: ext },
    });
  } else {
    signals.push({
      code: "DOC_INTEGRITY_OK",
      threatCode: "T021",
      severity: "low",
      score: 0,
      status: "passed",
      title: "Document integrity",
      description: "SHA-256 computed; office document signature looks consistent.",
      evidence: { sha256, magic, extension: ext },
    });
  }

  if (magic) {
    signals.push({
      code: "DOC_TYPE_RECORDED",
      threatCode: "T023",
      severity: "low",
      score: 0,
      status: "info",
      title: "Document type recorded",
      description: `Detected office container type "${magic}".`,
      evidence: { magic, extension: ext },
    });
  }

  return { sha256, sizeBytes: buffer.length, signals };
}

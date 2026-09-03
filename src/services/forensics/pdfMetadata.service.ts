import fs from "fs";
import type { ForensicSignal } from "./fileIntegrity.service";

export type PdfMetadata = {
  creator: string | null;
  producer: string | null;
  creationDate: string | null;
  modDate: string | null;
  title: string | null;
  author: string | null;
};

function decodePdfDate(raw: string | null): Date | null {
  if (!raw) return null;
  // D:YYYYMMDDHHmmSSOHH'mm'
  const m = raw.match(
    /D:(\d{4})(\d{2})(\d{2})(?:(\d{2})(\d{2})(\d{2}))?/
  );
  if (!m) return null;
  const [, y, mo, d, h = "0", mi = "0", s = "0"] = m;
  const dt = new Date(
    Date.UTC(
      Number(y),
      Number(mo) - 1,
      Number(d),
      Number(h),
      Number(mi),
      Number(s)
    )
  );
  return Number.isNaN(dt.getTime()) ? null : dt;
}

function extractInfoString(infoBlock: string, key: string): string | null {
  const patterns = [
    new RegExp(`/${key}\\s*\\((?:\\\\.|[^\\\\)])*\\)`, "i"),
    new RegExp(`/${key}\\s*<([0-9A-Fa-f]+)>`, "i"),
  ];
  for (const re of patterns) {
    const match = infoBlock.match(re);
    if (!match?.[0]) continue;
    const full = match[0];
    const paren = full.match(/\(([\s\S]*)\)\s*$/);
    if (paren?.[1] != null) {
      return paren[1]
        .replace(/\\([nrt\\()])/g, (_, c: string) => {
          if (c === "n") return "\n";
          if (c === "r") return "\r";
          if (c === "t") return "\t";
          return c;
        })
        .trim();
    }
    const hex = full.match(/<([0-9A-Fa-f]+)>/);
    if (hex?.[1]) {
      try {
        return Buffer.from(hex[1], "hex").toString("utf8").replace(/\0/g, "").trim();
      } catch {
        return hex[1];
      }
    }
  }
  return null;
}

/**
 * Lightweight PDF Info dictionary parser (no native deps).
 * Works for common PDFs; encrypted/compressed Info may return nulls.
 */
export function extractPdfMetadata(filePath: string): PdfMetadata | null {
  const buf = fs.readFileSync(filePath);
  if (buf.length < 5 || buf.subarray(0, 5).toString("ascii") !== "%PDF-") {
    return null;
  }

  // Search near end first (Info usually near xref/trailer), then full file.
  const asLatin = buf.toString("latin1");
  const trailerSlice = asLatin.slice(Math.max(0, asLatin.length - 256_000));
  const infoMatch =
    trailerSlice.match(/\/Info\s+(\d+)\s+\d+\s+R/i) ||
    asLatin.match(/\/Info\s+(\d+)\s+\d+\s+R/i);

  let infoBlock = trailerSlice;
  if (infoMatch) {
    const objNum = infoMatch[1];
    const objRe = new RegExp(
      `${objNum}\\s+\\d+\\s+obj[\\s\\S]{0,8000}?endobj`,
      "i"
    );
    const objBlock = asLatin.match(objRe)?.[0];
    if (objBlock) infoBlock = objBlock;
  }

  // Also scan for inline dictionary keys anywhere in trailer region
  const scan = `${infoBlock}\n${trailerSlice}`;

  return {
    creator: extractInfoString(scan, "Creator"),
    producer: extractInfoString(scan, "Producer"),
    creationDate: extractInfoString(scan, "CreationDate"),
    modDate: extractInfoString(scan, "ModDate"),
    title: extractInfoString(scan, "Title"),
    author: extractInfoString(scan, "Author"),
  };
}

const SUSPICIOUS_PRODUCERS = [
  /photoshop/i,
  /gimp/i,
  /illustrator/i,
  /canva/i,
  /snipping/i,
  /preview/i,
  /microsoft print to pdf/i,
  /chrome/i,
  /edge pdf/i,
  /foxit phantom/i,
];

/**
 * Metadata forensics for PDFs (T003–T005 style signals).
 */
export function analyzePdfMetadata(filePath: string): {
  metadata: PdfMetadata | null;
  signals: ForensicSignal[];
} {
  const metadata = extractPdfMetadata(filePath);
  const signals: ForensicSignal[] = [];

  if (!metadata) {
    signals.push({
      code: "PDF_METADATA_UNAVAILABLE",
      threatCode: "T003",
      severity: "low",
      score: 0,
      status: "info",
      title: "PDF metadata unavailable",
      description:
        "Could not read PDF Info dictionary (may be image-only, encrypted, or non-PDF).",
    });
    return { metadata: null, signals };
  }

  const created = decodePdfDate(metadata.creationDate);
  const modified = decodePdfDate(metadata.modDate);

  if (created && modified && modified.getTime() > created.getTime() + 60_000) {
    const deltaMin = Math.round((modified.getTime() - created.getTime()) / 60000);
    signals.push({
      code: "PDF_MODIFIED_AFTER_CREATE",
      threatCode: "T005",
      severity: "high",
      score: 22,
      status: "failed",
      title: "PDF modified after creation",
      description: `Modified Date is ${deltaMin} minute(s) later than Creation Date — may indicate post-creation edits.`,
      evidence: {
        creationDate: metadata.creationDate,
        modDate: metadata.modDate,
      },
    });
  } else if (created || modified) {
    signals.push({
      code: "PDF_DATE_CONSISTENT",
      threatCode: "T005",
      severity: "low",
      score: 0,
      status: "passed",
      title: "PDF dates consistent",
      description: "Creation/Modified dates do not show a clear post-edit gap.",
      evidence: {
        creationDate: metadata.creationDate,
        modDate: metadata.modDate,
      },
    });
  }

  const producer = metadata.producer || "";
  const creator = metadata.creator || "";
  const soft = `${producer} ${creator}`.trim();
  if (soft && SUSPICIOUS_PRODUCERS.some((re) => re.test(soft))) {
    signals.push({
      code: "PDF_PRODUCER_ANOMALY",
      threatCode: "T004",
      severity: "medium",
      score: 14,
      status: "failed",
      title: "Unusual PDF producer/creator",
      description: `Producer/Creator looks like an editor or print driver ("${soft.slice(0, 120)}"), not a typical HR/payroll exporter.`,
      evidence: { producer: metadata.producer, creator: metadata.creator },
    });
  } else if (soft) {
    signals.push({
      code: "PDF_PRODUCER_RECORDED",
      threatCode: "T004",
      severity: "low",
      score: 0,
      status: "info",
      title: "PDF producer recorded",
      description: `Producer/Creator: ${soft.slice(0, 160)}`,
      evidence: { producer: metadata.producer, creator: metadata.creator },
    });
  } else {
    signals.push({
      code: "PDF_PRODUCER_MISSING",
      threatCode: "T004",
      severity: "low",
      score: 6,
      status: "failed",
      title: "PDF producer missing",
      description: "Producer/Creator metadata is empty — common after stripping or reconstruction.",
    });
  }

  return { metadata, signals };
}

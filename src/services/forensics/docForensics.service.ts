import type { ForensicSignal } from "./fileIntegrity.service";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import zlib from "zlib";

function detectDocMagic(buf: Buffer): string | null {
  if (
    buf.length >= 8 &&
    buf[0] === 0xd0 &&
    buf[1] === 0xcf &&
    buf[2] === 0x11 &&
    buf[3] === 0xe0
  ) {
    return "ole";
  }
  if (
    buf.length >= 4 &&
    buf[0] === 0x50 &&
    buf[1] === 0x4b &&
    (buf[2] === 0x03 || buf[2] === 0x05 || buf[2] === 0x07)
  ) {
    return "ooxml";
  }
  if (buf.length >= 5 && buf.subarray(0, 5).toString("ascii") === "{\\rtf") return "rtf";
  return null;
}

function expectedDocMagic(ext: string): string | null {
  if (["doc", "xls", "ppt"].includes(ext)) return "ole";
  if (["docx", "xlsx", "pptx", "odt", "ods", "odp"].includes(ext)) return "ooxml";
  if (ext === "rtf") return "rtf";
  return null;
}

/** Minimal ZIP local-header reader (Store + Deflate) for OOXML introspection. */
function readZipEntries(
  buf: Buffer,
  maxEntries = 80
): Array<{ name: string; data: Buffer }> {
  const out: Array<{ name: string; data: Buffer }> = [];
  let i = 0;
  while (i < buf.length - 30 && out.length < maxEntries) {
    if (buf[i] !== 0x50 || buf[i + 1] !== 0x4b || buf[i + 2] !== 0x03 || buf[i + 3] !== 0x04) {
      i++;
      continue;
    }
    const compression = buf.readUInt16LE(i + 8);
    const flags = buf.readUInt16LE(i + 6);
    const compSize = buf.readUInt32LE(i + 18);
    const nameLen = buf.readUInt16LE(i + 26);
    const extraLen = buf.readUInt16LE(i + 28);
    const name = buf.subarray(i + 30, i + 30 + nameLen).toString("utf8");
    const dataStart = i + 30 + nameLen + extraLen;

    // Skip data-descriptor entries (size unknown without full parse)
    if (flags & 0x08) {
      i = dataStart;
      continue;
    }

    const compressed = buf.subarray(dataStart, Math.min(buf.length, dataStart + compSize));
    try {
      let data: Buffer;
      if (compression === 0) data = Buffer.from(Uint8Array.from(compressed));
      else if (compression === 8) {
        data = zlib.inflateRawSync(Uint8Array.from(compressed));
      } else {
        i = dataStart + compSize;
        continue;
      }
      out.push({ name, data });
    } catch {
      /* ignore corrupt entry */
    }
    i = dataStart + compSize;
  }
  return out;
}

function xmlTag(text: string, localName: string): string | null {
  const re = new RegExp(
    `<(?:[a-zA-Z0-9]+:)?${localName}[^>]*>([^<]{1,500})</(?:[a-zA-Z0-9]+:)?${localName}>`,
    "i"
  );
  const m = text.match(re);
  return m?.[1]?.trim() || null;
}

function analyzeOoxml(buf: Buffer): ForensicSignal[] {
  const signals: ForensicSignal[] = [];
  const entries = readZipEntries(buf);
  if (!entries.length) {
    signals.push({
      code: "DOC_OOXML_UNREADABLE",
      threatCode: "T024",
      severity: "medium",
      score: 10,
      status: "failed",
      title: "Office package unreadable",
      description: "Could not open OOXML ZIP entries for metadata / revision inspection.",
    });
    return signals;
  }

  const byName = new Map(entries.map((e) => [e.name.replace(/\\/g, "/").toLowerCase(), e.data]));
  const core =
    byName.get("docprops/core.xml")?.toString("utf8") ||
    byName.get("docprops\\core.xml")?.toString("utf8") ||
    "";
  const app =
    byName.get("docprops/app.xml")?.toString("utf8") ||
    byName.get("docprops\\app.xml")?.toString("utf8") ||
    "";

  const created = xmlTag(core, "created") || xmlTag(core, "dcterms:created");
  const modified = xmlTag(core, "modified") || xmlTag(core, "dcterms:modified");
  const lastModifiedBy = xmlTag(core, "lastModifiedBy") || xmlTag(core, "cp:lastModifiedBy");
  const revision = xmlTag(core, "revision") || xmlTag(core, "cp:revision");
  const application = xmlTag(app, "Application") || xmlTag(app, "application");

  if (created && modified) {
    const c = Date.parse(created);
    const m = Date.parse(modified);
    if (Number.isFinite(c) && Number.isFinite(m) && m - c > 60_000) {
      const deltaMin = Math.round((m - c) / 60000);
      signals.push({
        code: "DOC_MODIFIED_AFTER_CREATE",
        threatCode: "T025",
        severity: "high",
        score: 24,
        status: "failed",
        title: "Office document modified after creation",
        description: `core.xml Modified is ${deltaMin} minute(s) after Created — document was re-saved / edited.`,
        evidence: { created, modified, lastModifiedBy, revision },
      });
    } else {
      signals.push({
        code: "DOC_DATES_CONSISTENT",
        threatCode: "T025",
        severity: "low",
        score: 0,
        status: "passed",
        title: "Office dates consistent",
        description: "Created/Modified timestamps do not show a clear post-edit gap.",
        evidence: { created, modified },
      });
    }
  }

  const revNum = revision ? Number(revision) : NaN;
  if (Number.isFinite(revNum) && revNum >= 3) {
    signals.push({
      code: "DOC_HIGH_REVISION",
      threatCode: "T026",
      severity: "medium",
      score: 14,
      status: "failed",
      title: "High document revision count",
      description: `Revision="${revision}" suggests multiple edits before upload.`,
      evidence: { revision, lastModifiedBy, application },
    });
  }

  const SUSPICIOUS_APPS = [/libreoffice/i, /openoffice/i, /wps/i, /onlyoffice/i, /google/i];
  if (application && SUSPICIOUS_APPS.some((re) => re.test(application))) {
    signals.push({
      code: "DOC_APP_ANOMALY",
      threatCode: "T027",
      severity: "medium",
      score: 12,
      status: "failed",
      title: "Unusual office application",
      description: `Document produced/edited with "${application}" — verify against expected payroll/HR exporter.`,
      evidence: { application },
    });
  } else if (application) {
    signals.push({
      code: "DOC_APP_RECORDED",
      threatCode: "T027",
      severity: "low",
      score: 0,
      status: "info",
      title: "Office application recorded",
      description: `Application: ${application}`,
      evidence: { application, lastModifiedBy },
    });
  }

  // Scan document XML parts for tracked changes / comments (text removal & inserts)
  let hasDel = false;
  let hasIns = false;
  let hasComments = false;
  for (const [name, data] of byName) {
    if (!name.endsWith(".xml")) continue;
    if (
      !name.includes("document") &&
      !name.includes("sheet") &&
      !name.includes("slide") &&
      !name.includes("comments")
    ) {
      continue;
    }
    const xml = data.toString("latin1");
    if (/w:del[\s>]|w:deletion/i.test(xml)) hasDel = true;
    if (/w:ins[\s>]|w:insertion/i.test(xml)) hasIns = true;
    if (/w:comment|comments\/comment/i.test(xml) || name.includes("comments")) hasComments = true;
  }

  if (hasDel || hasIns || hasComments) {
    const parts = [
      hasDel ? "deletions" : null,
      hasIns ? "insertions" : null,
      hasComments ? "comments" : null,
    ].filter(Boolean);
    signals.push({
      code: "DOC_TRACKED_CHANGES",
      threatCode: "T028",
      severity: "high",
      score: 30,
      status: "failed",
      title: "Tracked changes / comments present",
      description: `Office package contains ${parts.join(
        ", "
      )} — text was added or removed with revision markup.`,
      evidence: { hasDel, hasIns, hasComments },
    });
  } else {
    signals.push({
      code: "DOC_TRACKED_CHANGES_CLEAR",
      threatCode: "T028",
      severity: "low",
      score: 0,
      status: "passed",
      title: "No tracked changes markup",
      description: "No w:del / w:ins / comments markup found in package XML.",
    });
  }

  return signals;
}

export function analyzeDocForensics(
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

  if (magic === "ooxml") {
    signals.push(...analyzeOoxml(buffer));
  } else if (magic === "rtf") {
    const rtf = buffer.toString("latin1");
    if (/\\highlight|\\strike|\\ul\b|\\revised/i.test(rtf)) {
      signals.push({
        code: "DOC_RTF_MARKUP_EDITS",
        threatCode: "T029",
        severity: "high",
        score: 22,
        status: "failed",
        title: "RTF edit markup detected",
        description: "RTF contains highlight/strike/underline/revision control words.",
      });
    }
  }

  return { sha256, sizeBytes: buffer.length, signals };
}

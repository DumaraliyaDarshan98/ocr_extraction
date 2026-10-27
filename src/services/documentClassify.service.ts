import fs from "fs";
import path from "path";
import sharp from "sharp";
import { extractText } from "./ocr.service";
import { validateAadhaar } from "../validators/aadhaar.validator";
import { validatePAN } from "../validators/pan.validator";
import { validatePassport } from "../validators/passport.validator";
import { validateDrivingLicense } from "../validators/drivingLicense.validator";

export type ClassifiedDocument = {
  documentType: string;
  confidence: number;
  evidence: string[];
  ocrText: string;
  extractedData: Record<string, unknown>;
};

const KNOWN_LABELS = [
  "PAN",
  "Aadhaar",
  "Voter Card",
  "Driving License",
  "Passport",
  "Salary Slip",
  "Form 16",
  "Bank Statement",
  "ITR",
  "GST",
  "Trade License",
  "Udyam Certificate",
  "Leaving Certificate",
  "Marksheet",
  "Address Proof",
  "Agreement",
  "Ownership Deed",
  "Other",
] as const;

type Candidate = {
  label: (typeof KNOWN_LABELS)[number];
  score: number;
  evidence: string[];
  extracted: Record<string, unknown>;
};

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function includesAny(text: string, needles: string[]): boolean {
  return needles.some((n) => includesNeedle(text, n));
}

/** Short ASCII tokens (e.g. "tan") must be whole words — "tan" must not match "standard". */
function includesNeedle(text: string, needle: string): boolean {
  const n = needle.toLowerCase().trim();
  if (!n) return false;
  const isAscii = /^[\x00-\x7F]+$/.test(n);
  if (isAscii && (n.length <= 4 || !n.includes(" "))) {
    return new RegExp(`\\b${escapeRegExp(n)}\\b`, "i").test(text);
  }
  return text.includes(n);
}

function countHits(text: string, needles: string[]): number {
  return needles.filter((n) => includesNeedle(text, n)).length;
}

/**
 * Preprocess image for more reliable local OCR (grayscale + contrast).
 */
async function prepareForLocalOcr(filePath: string): Promise<string> {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".pdf") return filePath;

  const outPath = path.join(
    path.dirname(filePath),
    `${path.basename(filePath, ext)}.ocrprep.png`,
  );
  try {
    await sharp(filePath)
      .rotate()
      .grayscale()
      .normalize()
      .sharpen()
      .png()
      .toFile(outPath);
    return outPath;
  } catch {
    return filePath;
  }
}

function extractDob(text: string): string | null {
  const m =
    text.match(/\b(\d{2}[\/\-.]\d{2}[\/\-.]\d{4})\b/) ||
    text.match(/\b(\d{4}[\/\-.]\d{2}[\/\-.]\d{2})\b/) ||
    text.match(/\byear of birth[:\s]*(\d{4})\b/i) ||
    text.match(/\byob[:\s]*(\d{4})\b/i);
  return m?.[1] ?? null;
}

function extractGender(text: string): string | null {
  if (/\bfemale\b|\b\/\s*f\b|\bsex[:\s]*f\b/i.test(text)) return "Female";
  if (/\bmale\b|\b\/\s*m\b|\bsex[:\s]*m\b/i.test(text)) return "Male";
  return null;
}

function extractLikelyName(text: string): string | null {
  const lines = text
    .split(/\n+/)
    .map((l) => l.replace(/\s+/g, " ").trim())
    .filter(Boolean);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (/^(name|naam)\b[:\s]/i.test(line)) {
      const after = line.replace(/^(name|naam)\b[:\s]*/i, "").trim();
      if (after && /[a-zA-Z]{3,}/.test(after)) return after.slice(0, 80);
      const next = lines[i + 1];
      if (next && /[a-zA-Z]{3,}/.test(next) && !/\d{4}/.test(next)) {
        return next.slice(0, 80);
      }
    }
  }
  return null;
}

function scoreAadhaar(text: string): Candidate | null {
  const evidence: string[] = [];
  let score = 0;
  const extracted: Record<string, unknown> = {};

  const aadhaar = validateAadhaar(text);
  if (aadhaar.valid && aadhaar.number) {
    score += 0.55;
    evidence.push("verhoeff_aadhaar");
    extracted.aadhaarNumber = aadhaar.number;
    extracted.aadhaarFormatValid = true;
  } else if (/\b\d{4}\s?\d{4}\s?\d{4}\b/.test(text)) {
    score += 0.2;
    evidence.push("12_digit_pattern");
    extracted.aadhaarFormatValid = false;
  }

  const keywordHits = countHits(text, [
    "aadhaar",
    "aadhar",
    "uidai",
    "unique identification authority",
    "government of india",
    "मेरा आधार",
    "आधार",
  ]);
  if (keywordHits > 0) {
    score += Math.min(0.35, keywordHits * 0.12);
    evidence.push(`aadhaar_keywords:${keywordHits}`);
  }

  const dob = extractDob(text);
  if (dob) {
    score += 0.05;
    extracted.dob = dob;
    evidence.push("dob");
  }
  const gender = extractGender(text);
  if (gender) {
    score += 0.05;
    extracted.gender = gender;
    evidence.push("gender");
  }
  const name = extractLikelyName(text);
  if (name) {
    score += 0.05;
    extracted.name = name;
    evidence.push("name");
  }

  if (score < 0.35) return null;
  return {
    label: "Aadhaar",
    score: Math.min(0.98, score),
    evidence,
    extracted,
  };
}

function scorePan(text: string): Candidate | null {
  const evidence: string[] = [];
  let score = 0;
  const extracted: Record<string, unknown> = {};
  const upper = text.toUpperCase();
  const pan = validatePAN(upper);
  if (pan.valid && pan.number) {
    score += 0.55;
    evidence.push("pan_pattern");
    extracted.panNumber = pan.number;
  }
  const hits = countHits(text, [
    "income tax department",
    "permanent account number",
    "govt. of india",
    "government of india",
    "pan",
  ]);
  if (hits > 0) {
    score += Math.min(0.35, hits * 0.1);
    evidence.push(`pan_keywords:${hits}`);
  }
  if (score < 0.4) return null;
  return { label: "PAN", score: Math.min(0.96, score), evidence, extracted };
}

function scorePassport(text: string): Candidate | null {
  const evidence: string[] = [];
  let score = 0;
  const extracted: Record<string, unknown> = {};
  const upper = text.toUpperCase();
  const passport = validatePassport(upper);
  if (passport.valid && passport.number) {
    score += 0.45;
    evidence.push("passport_pattern");
    extracted.passportNumber = passport.number;
  }
  const hits = countHits(text, [
    "republic of india",
    "passport",
    "nationality",
    "place of birth",
  ]);
  if (hits > 0) {
    score += Math.min(0.4, hits * 0.12);
    evidence.push(`passport_keywords:${hits}`);
  }
  if (score < 0.4) return null;
  return {
    label: "Passport",
    score: Math.min(0.95, score),
    evidence,
    extracted,
  };
}

function scoreDl(text: string): Candidate | null {
  // Udyam / trade / other "license" docs must not score as DL.
  if (
    /udyam|udyog aadhaar|msme|leaving certificate|statement of marks|mark\s*sheet/.test(
      text,
    )
  ) {
    return null;
  }
  const evidence: string[] = [];
  let score = 0;
  const extracted: Record<string, unknown> = {};
  const upper = text.toUpperCase();
  const dl = validateDrivingLicense(upper);
  const hits = countHits(text, [
    "driving licence",
    "driving license",
    "transport department",
    "indian union",
    "licensing authority",
    "rto",
  ]);
  // DL number alone is weak — many IDs look similar; require DL keywords too.
  if (dl.valid && dl.number && hits > 0) {
    score += 0.45;
    evidence.push("dl_pattern");
    extracted.dlNumber = dl.number;
  } else if (dl.valid && dl.number) {
    score += 0.2;
    evidence.push("dl_pattern_weak");
    extracted.dlNumber = dl.number;
  }
  if (hits > 0) {
    score += Math.min(0.4, hits * 0.12);
    evidence.push(`dl_keywords:${hits}`);
  }
  if (score < 0.4) return null;
  return {
    label: "Driving License",
    score: Math.min(0.95, score),
    evidence,
    extracted,
  };
}

function scoreLeavingCertificate(text: string): Candidate | null {
  const needles = [
    "leaving certificate",
    "school leaving",
    "l.c. no",
    "lc no",
    "date of leaving school",
    "reason for leaving",
    "last school attended",
    "transfer certificate",
  ];
  const hits = countHits(text, needles);
  const schoolish =
    countHits(text, [
      "high school",
      "secondary school",
      "std",
      "standard",
      "conduct",
      "progress",
      "g.r. no",
      "gr no",
    ]) >= 2;
  if (hits < 1 && !(schoolish && /leaving|certificate/.test(text))) return null;
  const score = Math.min(0.96, 0.45 + hits * 0.15 + (schoolish ? 0.15 : 0));
  return {
    label: "Leaving Certificate",
    score,
    evidence: [`leaving_certificate_keywords:${hits}`],
    extracted: {},
  };
}

function scoreMarksheet(text: string): Candidate | null {
  const needles = [
    "statement of marks",
    "mark sheet",
    "marksheet",
    "marks sheet",
    "higher secondary certificate examination",
    "secondary & higher secondary",
    "secondary and higher secondary",
    "over all grade",
    "overall grade",
    "percentile rank",
    "science stream",
    "seat no",
  ];
  const hits = countHits(text, needles);
  const boardish = countHits(text, [
    "education board",
    "examination secretary",
    "subject",
    "theory total",
    "total marks",
  ]);
  if (hits < 1 && boardish < 2) return null;
  const score = Math.min(0.96, 0.4 + hits * 0.14 + boardish * 0.08);
  if (score < 0.45) return null;
  return {
    label: "Marksheet",
    score,
    evidence: [`marksheet_keywords:${hits}`, `board_signals:${boardish}`],
    extracted: {},
  };
}

function scoreUdyam(text: string): Candidate | null {
  const needles = [
    "udyam",
    "udyog aadhaar",
    "udyam registration",
    "ministry of micro",
    "msme",
    "micro, small and medium",
    "micro small and medium",
  ];
  const hits = countHits(text, needles);
  const hasUdyamId = /\budyam[-\s]?[a-z]{2}[-\s]?\d{2}[-\s]?\d{5,}/i.test(text);
  if (hits < 1 && !hasUdyamId) return null;
  const score = Math.min(0.97, 0.5 + hits * 0.12 + (hasUdyamId ? 0.25 : 0));
  return {
    label: "Udyam Certificate",
    score,
    evidence: [
      `udyam_keywords:${hits}`,
      ...(hasUdyamId ? ["udyam_id_pattern"] : []),
    ],
    extracted: {},
  };
}

function scoreVoter(text: string): Candidate | null {
  const hits = countHits(text, [
    "election commission of india",
    "electors photo identity card",
    "epic",
    "voter",
  ]);
  if (hits < 1) return null;
  return {
    label: "Voter Card",
    score: Math.min(0.9, 0.35 + hits * 0.15),
    evidence: [`voter_keywords:${hits}`],
    extracted: {},
  };
}

function scoreFinancial(text: string): Candidate | null {
  const checks: Array<{
    label: (typeof KNOWN_LABELS)[number];
    needles: string[];
  }> = [
    {
      label: "Bank Statement",
      needles: ["bank statement", "ifsc", "account number", "statement of account"],
    },
    {
      label: "Salary Slip",
      needles: ["salary slip", "payslip", "net salary", "gross salary"],
    },
    {
      label: "Form 16",
      // Do NOT use bare "tan" — it matches inside "standard" on school LCs.
      needles: [
        "form 16",
        "form16",
        "form no. 16",
        "form no 16",
        "tds certificate",
        "certificate under section 203",
        "tax deduction at source",
        "deduction and collection account",
      ],
    },
    {
      label: "ITR",
      needles: ["income tax return", "itr-", "acknowledgement number"],
    },
    {
      label: "GST",
      needles: ["gstin", "goods and services tax", "gst return"],
    },
    {
      label: "Trade License",
      needles: ["trade license", "trade licence"],
    },
  ];

  let best: Candidate | null = null;
  for (const c of checks) {
    const hits = countHits(text, c.needles);
    if (hits < 1) continue;
    const score = Math.min(0.9, 0.3 + hits * 0.18);
    if (!best || score > best.score) {
      best = {
        label: c.label,
        score,
        evidence: [`${c.label.toLowerCase().replace(/\s+/g, "_")}_keywords:${hits}`],
        extracted: {},
      };
    }
  }
  return best;
}

/**
 * Local (Tesseract + validators) document classification.
 * Used when Gemini is down / misclassifies, and to cross-check AI results.
 */
export async function classifyDocumentLocally(
  filePath: string,
  mimeTypeHint?: string,
): Promise<ClassifiedDocument> {
  const absolute = path.resolve(filePath);
  const prepPath = await prepareForLocalOcr(absolute);
  let ocrText = "";
  try {
    ocrText = await extractText(prepPath, mimeTypeHint || "image/png");
  } catch (err) {
    console.warn("[OCR:CLASSIFY] local OCR failed", err);
  } finally {
    if (prepPath !== absolute && fs.existsSync(prepPath)) {
      try {
        fs.unlinkSync(prepPath);
      } catch {
        /* ignore */
      }
    }
  }

  const text = (ocrText || "").toLowerCase();
  if (!text.trim()) {
    return {
      documentType: "Other",
      confidence: 0,
      evidence: ["empty_ocr"],
      ocrText: "",
      extractedData: {},
    };
  }

  const candidates = [
    scoreAadhaar(text),
    scorePan(text),
    scorePassport(text),
    scoreDl(text),
    scoreVoter(text),
    scoreLeavingCertificate(text),
    scoreMarksheet(text),
    scoreUdyam(text),
    scoreFinancial(text),
  ].filter((c): c is Candidate => !!c);

  candidates.sort((a, b) => b.score - a.score);
  const top = candidates[0];
  if (!top || top.score < 0.4) {
    return {
      documentType: "Other",
      confidence: top?.score ?? 0,
      evidence: top?.evidence ?? ["no_strong_signal"],
      ocrText: text.slice(0, 4000),
      extractedData: top?.extracted ?? {},
    };
  }

  console.log(
    `[OCR:CLASSIFY] local → ${top.label} conf=${top.score.toFixed(2)} evidence=${top.evidence.join(",")}`,
  );

  return {
    documentType: top.label,
    confidence: top.score,
    evidence: top.evidence,
    ocrText: text.slice(0, 4000),
    extractedData: top.extracted,
  };
}

/** Canonical internal type used by verify / RCU mapping. */
export function toInternalDocumentType(label: string): string {
  const t = (label || "").trim().toLowerCase();
  if (/aadhaar|aadhar/.test(t)) return "aadhaar";
  if (/\bpan\b/.test(t)) return "pan";
  if (/voter/.test(t)) return "voter card";
  if (/udyam|udyog\s*aadhaar|msme\s*reg/.test(t)) return "udyam certificate";
  if (/leaving\s*certificate|\bschool\s*leaving\b|\blc\b/.test(t)) {
    return "leaving certificate";
  }
  if (/mark\s*sheet|marksheet|statement\s*of\s*marks/.test(t)) return "marksheet";
  // Require "driving" — bare "license/licence" must not swallow Trade/Udyam.
  if (/driving\s*(licen[cs]e)?|\bdl\b/.test(t) && !/trade|udyam|business/.test(t)) {
    return "driving license";
  }
  if (/passport/.test(t)) return "passport";
  if (/salary/.test(t)) return "salary slip";
  if (/form\s*16|tds\s*certificate/.test(t)) return "form 16";
  if (/bank/.test(t)) return "bank statement";
  if (/\bitr\b/.test(t)) return "itr";
  if (/\bgst\b/.test(t)) return "gst";
  if (/trade\s*(licen[cs]e)?/.test(t)) return "trade license";
  if (/address/.test(t)) return "address proof";
  if (/agreement/.test(t)) return "agreement";
  if (/ownership|deed/.test(t)) return "ownership deed";
  if (!t || t === "other" || t === "other docs" || t === "unknown") return "other";
  return t;
}

/**
 * Override AI mislabels using strong OCR title/keyword evidence
 * (LC/marksheet → Form 16/TDS; Udyam → Driving License).
 */
export function correctMisclassifiedType(
  documentType: string,
  ocrText: string,
): string {
  const text = (ocrText || "").toLowerCase();
  if (!text.trim()) return documentType;

  if (
    /udyam|udyog aadhaar|udyam registration|ministry of micro/.test(text) ||
    /\budyam[-\s]?[a-z]{2}[-\s]?\d{2}/i.test(ocrText)
  ) {
    return "Udyam Certificate";
  }
  if (
    /leaving certificate|date of leaving school|reason for leaving school|last school attended|\bl\.?\s*c\.?\s*no\b/.test(
      text,
    )
  ) {
    return "Leaving Certificate";
  }
  if (
    /statement of marks|mark\s*sheet|marksheet|higher secondary certificate examination|percentile rank|over all grade/.test(
      text,
    )
  ) {
    return "Marksheet";
  }
  return documentType;
}

export function isWeakOrOtherType(documentType: string): boolean {
  const t = toInternalDocumentType(documentType);
  return !t || t === "other" || t === "unknown";
}

export function hasGeminiApiKey(): boolean {
  return Boolean(
    String(process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || "").trim(),
  );
}

/** Merge AI + local signals; never trust a lone failed AI "Other" over strong ID evidence. */
export function fuseDocumentTypes(
  ai: { documentType: string; confidence: number } | null,
  local: ClassifiedDocument,
): { documentType: string; confidence: number; source: string } {
  const aiType = ai?.documentType?.trim() || "";
  const aiConf = ai?.confidence ?? 0;
  const aiWeak =
    !ai ||
    aiConf < 0.55 ||
    isWeakOrOtherType(aiType) ||
    aiType.toLowerCase() === "unknown";

  const localStrong =
    !isWeakOrOtherType(local.documentType) && local.confidence >= 0.55;

  if (aiWeak && localStrong) {
    return {
      documentType: local.documentType,
      confidence: local.confidence,
      source: "local_ocr",
    };
  }

  if (!aiWeak && localStrong) {
    const sameFamily =
      toInternalDocumentType(aiType) === toInternalDocumentType(local.documentType);
    if (sameFamily) {
      return {
        documentType: aiType,
        confidence: Math.max(aiConf, local.confidence),
        source: "ai+local",
      };
    }
    const localInternal = toInternalDocumentType(local.documentType);
    const aiInternal = toInternalDocumentType(aiType);
    // School LC / marksheet / Udyam beat a conflicting Form 16 or Driving License guess.
    const localEducationOrUdyam =
      localInternal === "leaving certificate" ||
      localInternal === "marksheet" ||
      localInternal === "udyam certificate";
    const aiForm16OrDl =
      aiInternal === "form 16" || aiInternal === "driving license";
    if (localEducationOrUdyam && aiForm16OrDl && local.confidence >= 0.55) {
      return {
        documentType: local.documentType,
        confidence: Math.max(local.confidence, 0.85),
        source: "local_override_edu_udyam",
      };
    }
    // Strong Aadhaar Verhoeff / PAN pattern beats a conflicting weak AI guess.
    if (local.confidence >= 0.75 && aiConf < 0.85) {
      return {
        documentType: local.documentType,
        confidence: local.confidence,
        source: "local_override",
      };
    }
  }

  if (!aiWeak) {
    return {
      documentType: aiType,
      confidence: aiConf,
      source: "gemini",
    };
  }

  return {
    documentType: local.documentType || "Other",
    confidence: local.confidence,
    source: localStrong ? "local_ocr" : "fallback_other",
  };
}

export function includesDocKeyword(type: string, text: string): boolean {
  return includesAny(text.toLowerCase(), [
    type.toLowerCase(),
    ...(type.toLowerCase().includes("aadhaar")
      ? ["aadhaar", "aadhar", "uidai"]
      : []),
  ]);
}

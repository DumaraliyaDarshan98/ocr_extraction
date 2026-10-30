/**
 * Banking-grade document validation — separate from identification, extraction,
 * and authenticity/forensics. OCR text alone never proves authenticity.
 */
import { validateAadhaar } from "../validators/aadhaar.validator";
import { validatePAN } from "../validators/pan.validator";
import { validatePassport } from "../validators/passport.validator";
import { validateDrivingLicense } from "../validators/drivingLicense.validator";
import {
  hasStrongUdyamSignals,
  toInternalDocumentType,
} from "./documentClassify.service";

/** Per-document banking validation outcome (not case workflow status). */
export type DocumentValidationStatus =
  | "VALID"
  | "NEEDS_REVIEW"
  | "INVALID"
  | "PROCESSING_FAILED";

export type FieldValidationSeverity = "error" | "warning" | "info";

export type FieldValidationResult = {
  field: string;
  status: "passed" | "failed" | "missing" | "skipped" | "low_confidence";
  severity: FieldValidationSeverity;
  message: string;
  valuePreview?: string | null;
};

export type DocumentValidationReport = {
  status: DocumentValidationStatus;
  statusLabel: string;
  /** Human-readable reasons (ordered: blockers first). */
  reasons: string[];
  fieldResults: FieldValidationResult[];
  /** Identification step outcome (separate from field checks). */
  identification: {
    documentType: string;
    confidence: number;
    accepted: boolean;
    uncertain: boolean;
  };
  /** Explicit disclaimer — extraction ≠ authenticity. */
  authenticityNote: string;
  /** Trace / debug metadata for auditors. */
  trace: {
    sourceFile?: string | null;
    identifySource?: string | null;
    extractionOk: boolean;
    requiredFieldCount: number;
    failedFieldCount: number;
    missingFieldCount: number;
    lowConfidenceFieldCount: number;
  };
};

/** Minimum identify confidence to accept a non-Other type without manual review. */
export const IDENTIFY_ACCEPT_CONFIDENCE = 0.55;
/** Below this, refuse the type entirely (treat as unknown). */
export const IDENTIFY_REFUSE_CONFIDENCE = 0.4;
/** Per-field confidence below this → needs review, not silent accept. */
export const FIELD_CONFIDENCE_REVIEW = 0.55;

const AUTHENTICITY_NOTE =
  "OCR identification and extraction do not prove document authenticity. " +
  "Forensic/tamper signals and portal checks are separate steps. " +
  "Where automated verification is incomplete, the document is flagged for manual review.";

type RequiredFieldSpec = {
  field: string;
  label: string;
  /** Alternate keys accepted from extraction payloads. */
  aliases?: string[];
  validate?: (raw: string, all: Record<string, unknown>) => boolean;
  formatHint?: string;
};

const REQUIRED_BY_TYPE: Record<string, RequiredFieldSpec[]> = {
  aadhaar: [
    {
      field: "aadhaarNumber",
      label: "Aadhaar number",
      aliases: ["uid", "aadhaar", "aadharNumber"],
      validate: (v) => validateAadhaar(v.replace(/\s/g, "")).valid,
      formatHint: "12-digit UID with valid Verhoeff checksum",
    },
    {
      field: "name",
      label: "Name",
      aliases: ["fullName", "holderName"],
    },
  ],
  pan: [
    {
      field: "panNumber",
      label: "PAN",
      aliases: ["pan"],
      validate: (v) => validatePAN(v.toUpperCase()).valid,
      formatHint: "AAAAA9999A",
    },
    {
      field: "name",
      label: "Name",
      aliases: ["fullName", "holderName"],
    },
  ],
  passport: [
    {
      field: "passportNumber",
      label: "Passport number",
      aliases: ["passport"],
      validate: (v) => validatePassport(v.toUpperCase()).valid,
    },
    {
      field: "name",
      label: "Name",
      aliases: ["fullName", "surname", "givenName"],
    },
  ],
  "driving license": [
    {
      field: "dlNumber",
      label: "DL number",
      aliases: ["licenseNumber", "drivingLicenseNumber", "dl"],
      validate: (v) => validateDrivingLicense(v.toUpperCase()).valid,
    },
    {
      field: "name",
      label: "Name",
      aliases: ["fullName", "holderName"],
    },
  ],
  "voter card": [
    {
      field: "voterId",
      label: "Voter ID",
      aliases: ["epicNumber", "voterNumber", "epic"],
    },
    {
      field: "name",
      label: "Name",
      aliases: ["fullName"],
    },
  ],
  "udyam certificate": [
    {
      field: "udyamRegistrationNumber",
      label: "Udyam registration number",
      aliases: ["udyamNumber", "udyamId", "registrationNumber"],
      validate: (v) =>
        /\budyam[-\s]?[a-z]{2}[-\s]?\d{2}[-\s]?\d{5,}/i.test(v) ||
        /^[A-Z]{2}\d{2}[A-Z]\d+$/i.test(v.replace(/\s/g, "")),
      formatHint: "UDYAM-XX-##-######",
    },
    {
      field: "nameOfEnterprise",
      label: "Enterprise name",
      aliases: ["enterpriseName", "name", "businessName"],
    },
  ],
  "salary slip": [
    {
      field: "employeeName",
      label: "Employee name",
      aliases: ["name", "employee"],
    },
    {
      field: "netSalary",
      label: "Net salary",
      aliases: ["netPay", "takeHome", "netAmount"],
    },
  ],
  "form 16": [
    {
      field: "panNumber",
      label: "PAN",
      aliases: ["pan", "employeePan"],
      validate: (v) => validatePAN(v.toUpperCase()).valid,
    },
    {
      field: "employerName",
      label: "Employer / deductor",
      aliases: ["deductorName", "employer"],
    },
  ],
  "bank statement": [
    {
      field: "accountNumber",
      label: "Account number",
      aliases: ["accountNo", "acctNumber"],
    },
    {
      field: "bankName",
      label: "Bank name",
      aliases: ["bank"],
    },
  ],
  gst: [
    {
      field: "gstin",
      label: "GSTIN",
      aliases: ["gstNumber", "gst"],
      validate: (v) =>
        /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][A-Z0-9]Z[A-Z0-9]$/i.test(
          v.replace(/\s/g, ""),
        ),
    },
  ],
  itr: [
    {
      field: "acknowledgementNumber",
      label: "Acknowledgement number",
      aliases: ["ackNumber", "acknowledgement"],
    },
  ],
  "trade license": [
    {
      field: "licenseNumber",
      label: "License number",
      aliases: ["tradeLicenseNumber", "licenceNumber"],
    },
    {
      field: "businessName",
      label: "Business name",
      aliases: ["name", "enterpriseName"],
    },
  ],
  "leaving certificate": [
    {
      field: "studentName",
      label: "Student name",
      aliases: ["name", "pupilName"],
    },
    {
      field: "schoolName",
      label: "School name",
      aliases: ["institutionName", "school"],
    },
  ],
  marksheet: [
    {
      field: "candidateName",
      label: "Candidate name",
      aliases: ["name", "studentName"],
    },
    {
      field: "rollNumber",
      label: "Roll / seat number",
      aliases: ["seatNumber", "rollNo"],
    },
  ],
};

function statusLabel(status: DocumentValidationStatus): string {
  switch (status) {
    case "VALID":
      return "Valid";
    case "NEEDS_REVIEW":
      return "Needs Review";
    case "INVALID":
      return "Invalid";
    case "PROCESSING_FAILED":
      return "Processing Failed";
    default:
      return status;
  }
}

function getFieldValue(
  data: Record<string, unknown>,
  spec: RequiredFieldSpec,
): { key: string; value: string } | null {
  const keys = [spec.field, ...(spec.aliases ?? [])];
  for (const want of keys) {
    const target = want.toLowerCase();
    const found = Object.keys(data).find((k) => k.toLowerCase() === target);
    if (!found) continue;
    const raw = data[found];
    if (raw === null || raw === undefined) continue;
    const str = String(raw).trim();
    if (!str || /^n\/?a$/i.test(str) || str === "-" || str === "null") continue;
    return { key: found, value: str };
  }
  return null;
}

function preview(value: string, max = 48): string {
  const t = value.replace(/\s+/g, " ").trim();
  return t.length <= max ? t : `${t.slice(0, max - 1)}…`;
}

export type EvaluateDocumentValidationInput = {
  documentType: string;
  identifyConfidence: number;
  extractedData?: Record<string, unknown> | null;
  fieldConfidence?: Record<string, number> | null;
  ocrText?: string | null;
  extractionOk?: boolean;
  processingError?: string | null;
  identifySource?: string | null;
  sourceFileName?: string | null;
  /** Forensic verdict — authenticity is separate; only escalates to review. */
  forensicVerdict?: string | null;
  /** Hard ID checksum already failed (Aadhaar/PAN). */
  idChecksumFailed?: boolean;
};

/**
 * Decide whether identification confidence is enough to accept a typed document.
 * Low confidence → unknown (do not guess).
 */
export function resolveAcceptedDocumentType(
  rawType: string,
  confidence: number,
  ocrText?: string | null,
): {
  documentType: string;
  accepted: boolean;
  uncertain: boolean;
  reason?: string;
} {
  const internal = toInternalDocumentType(rawType || "other");
  const conf = Number.isFinite(confidence) ? confidence : 0;

  if (internal === "other" || internal === "unknown" || !internal) {
    return {
      documentType: "other",
      accepted: false,
      uncertain: true,
      reason: "Document type could not be identified with sufficient confidence",
    };
  }

  // Strong structural OCR evidence can accept slightly lower AI confidence.
  const strongUdyam =
    internal === "udyam certificate" && hasStrongUdyamSignals(ocrText || "");

  if (conf < IDENTIFY_REFUSE_CONFIDENCE && !strongUdyam) {
    return {
      documentType: "other",
      accepted: false,
      uncertain: true,
      reason: `Identification confidence too low (${conf.toFixed(2)}) — type not accepted`,
    };
  }

  if (conf < IDENTIFY_ACCEPT_CONFIDENCE && !strongUdyam) {
    return {
      documentType: internal,
      accepted: true,
      uncertain: true,
      reason: `Identification confidence marginal (${conf.toFixed(2)}) — requires manual review`,
    };
  }

  return {
    documentType: internal,
    accepted: true,
    uncertain: false,
  };
}

/**
 * Full banking validation report for one uploaded document.
 */
export function evaluateDocumentValidation(
  input: EvaluateDocumentValidationInput,
): DocumentValidationReport {
  const reasons: string[] = [];
  const fieldResults: FieldValidationResult[] = [];

  if (input.processingError) {
    reasons.push(input.processingError);
    return {
      status: "PROCESSING_FAILED",
      statusLabel: statusLabel("PROCESSING_FAILED"),
      reasons,
      fieldResults: [
        {
          field: "processing",
          status: "failed",
          severity: "error",
          message: input.processingError,
        },
      ],
      identification: {
        documentType: toInternalDocumentType(input.documentType || "other"),
        confidence: input.identifyConfidence ?? 0,
        accepted: false,
        uncertain: true,
      },
      authenticityNote: AUTHENTICITY_NOTE,
      trace: {
        sourceFile: input.sourceFileName ?? null,
        identifySource: input.identifySource ?? null,
        extractionOk: false,
        requiredFieldCount: 0,
        failedFieldCount: 1,
        missingFieldCount: 0,
        lowConfidenceFieldCount: 0,
      },
    };
  }

  const idRes = resolveAcceptedDocumentType(
    input.documentType,
    input.identifyConfidence,
    input.ocrText,
  );

  const identification = {
    documentType: idRes.documentType,
    confidence: input.identifyConfidence ?? 0,
    accepted: idRes.accepted,
    uncertain: idRes.uncertain,
  };

  if (idRes.reason) reasons.push(idRes.reason);

  const extractionOk = input.extractionOk !== false;
  if (!extractionOk) {
    reasons.push("Structured extraction did not complete successfully");
  }

  const data = (input.extractedData ?? {}) as Record<string, unknown>;
  const confMap = input.fieldConfidence ?? {};
  const specs = REQUIRED_BY_TYPE[idRes.documentType] ?? [];

  let failedFieldCount = 0;
  let missingFieldCount = 0;
  let lowConfidenceFieldCount = 0;

  if (idRes.accepted && specs.length > 0) {
    for (const spec of specs) {
      const found = getFieldValue(data, spec);
      if (!found) {
        missingFieldCount += 1;
        fieldResults.push({
          field: spec.field,
          status: "missing",
          severity: "error",
          message: `${spec.label} is required but was not extracted`,
          valuePreview: null,
        });
        reasons.push(`Missing required field: ${spec.label}`);
        continue;
      }

      const fieldConfRaw = confMap[found.key] ?? confMap[spec.field];
      const fieldConf =
        typeof fieldConfRaw === "number" && Number.isFinite(fieldConfRaw)
          ? fieldConfRaw
          : null;

      if (spec.validate && !spec.validate(found.value, data)) {
        failedFieldCount += 1;
        fieldResults.push({
          field: spec.field,
          status: "failed",
          severity: "error",
          message: `${spec.label} failed format/validation${
            spec.formatHint ? ` (${spec.formatHint})` : ""
          }`,
          valuePreview: preview(found.value),
        });
        reasons.push(`Invalid ${spec.label}`);
        continue;
      }

      if (fieldConf != null && fieldConf < FIELD_CONFIDENCE_REVIEW) {
        lowConfidenceFieldCount += 1;
        fieldResults.push({
          field: spec.field,
          status: "low_confidence",
          severity: "warning",
          message: `${spec.label} extracted with low confidence (${fieldConf.toFixed(2)})`,
          valuePreview: preview(found.value),
        });
        reasons.push(`Low-confidence field: ${spec.label}`);
        continue;
      }

      fieldResults.push({
        field: spec.field,
        status: "passed",
        severity: "info",
        message: `${spec.label} present${
          spec.validate ? " and format-validated" : ""
        }`,
        valuePreview: preview(found.value),
      });
    }
  } else if (idRes.accepted && specs.length === 0) {
    fieldResults.push({
      field: "_schema",
      status: "skipped",
      severity: "warning",
      message:
        "No mandatory field schema configured for this type — manual review recommended",
    });
    reasons.push("No mandatory field schema for this document type");
  }

  if (input.idChecksumFailed) {
    failedFieldCount += 1;
    reasons.push("Primary ID checksum/format validation failed");
  }

  const fx = String(input.forensicVerdict || "").toUpperCase();
  if (fx === "TEMP" || fx === "SUSPICIOUS" || fx === "MANUAL_REVIEW") {
    reasons.push(
      `Forensic verdict requires attention (${input.forensicVerdict}) — authenticity not confirmed`,
    );
  }

  // Decide status — never silently VALID when uncertain or incomplete.
  let status: DocumentValidationStatus;

  if (!idRes.accepted) {
    status = "NEEDS_REVIEW";
  } else if (!extractionOk) {
    status = "PROCESSING_FAILED";
  } else if (failedFieldCount > 0 || input.idChecksumFailed) {
    status = "INVALID";
  } else if (
    idRes.uncertain ||
    missingFieldCount > 0 ||
    lowConfidenceFieldCount > 0 ||
    specs.length === 0 ||
    fx === "TEMP" ||
    fx === "SUSPICIOUS" ||
    fx === "MANUAL_REVIEW"
  ) {
    status = "NEEDS_REVIEW";
  } else {
    status = "VALID";
  }

  // Deduplicate reasons while preserving order
  const uniqReasons = [...new Set(reasons.filter(Boolean))];

  return {
    status,
    statusLabel: statusLabel(status),
    reasons: uniqReasons.length
      ? uniqReasons
      : status === "VALID"
        ? ["Document identified and required fields validated"]
        : ["Validation incomplete"],
    fieldResults,
    identification,
    authenticityNote: AUTHENTICITY_NOTE,
    trace: {
      sourceFile: input.sourceFileName ?? null,
      identifySource: input.identifySource ?? null,
      extractionOk,
      requiredFieldCount: specs.length,
      failedFieldCount,
      missingFieldCount,
      lowConfidenceFieldCount,
    },
  };
}

/** Map banking status → legacy boolean isValid (only VALID is true). */
export function validationStatusToIsValid(
  status: DocumentValidationStatus,
): boolean {
  return status === "VALID";
}

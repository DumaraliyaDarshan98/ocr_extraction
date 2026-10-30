/**
 * Banking-grade validation smoke tests.
 * Run: npx ts-node --transpile-only src/scripts/smokeBankingValidation.ts
 */
import {
  evaluateDocumentValidation,
  resolveAcceptedDocumentType,
  validationStatusToIsValid,
} from "../services/documentValidation.service";
import { toInternalDocumentType } from "../services/documentClassify.service";

let failed = 0;

function assert(cond: boolean, msg: string) {
  if (!cond) {
    failed += 1;
    console.error(`FAIL: ${msg}`);
  } else {
    console.log(`OK:   ${msg}`);
  }
}

const UDYAM_OCR = `
UDYAM REGISTRATION CERTIFICATE
UDYAM REGISTRATION NUMBER UDYAM-MH-04-0294318
NAME OF ENTERPRISE SWARAJYA RESEARCH
NATIONAL INDUSTRY CLASSIFICATION
https://udyamregistration.gov.in
`.trim();

console.log("=== Banking validation smoke ===\n");

// --- Identification gate: never guess ---
{
  const low = resolveAcceptedDocumentType("Aadhaar", 0.2, "");
  assert(low.documentType === "other" && !low.accepted, "low conf Aadhaar → refused (other)");

  const mid = resolveAcceptedDocumentType("Aadhaar", 0.48, "uidai aadhaar");
  assert(mid.accepted && mid.uncertain, "marginal Aadhaar → accepted but uncertain");

  const ok = resolveAcceptedDocumentType("Aadhaar", 0.9, "uidai");
  assert(ok.accepted && !ok.uncertain, "high conf Aadhaar → accepted");

  const udyamStrong = resolveAcceptedDocumentType("Udyam Certificate", 0.35, UDYAM_OCR);
  assert(
    udyamStrong.accepted && toInternalDocumentType(udyamStrong.documentType) === "udyam certificate",
    "strong Udyam OCR accepts even at lower AI confidence",
  );
}

// --- VALID Udyam ---
{
  const report = evaluateDocumentValidation({
    documentType: "udyam certificate",
    identifyConfidence: 0.92,
    extractedData: {
      udyamRegistrationNumber: "UDYAM-MH-04-0294318",
      nameOfEnterprise: "SWARAJYA RESEARCH AND CONSULTANCY PRIVATE LIMITED",
    },
    fieldConfidence: {
      udyamRegistrationNumber: 0.95,
      nameOfEnterprise: 0.9,
    },
    ocrText: UDYAM_OCR,
    extractionOk: true,
  });
  assert(report.status === "VALID", `Udyam complete → VALID (got ${report.status})`);
  assert(validationStatusToIsValid(report.status), "VALID maps to isValid=true");
  assert(report.authenticityNote.includes("do not prove"), "authenticity disclaimer present");
}

// --- INVALID Aadhaar checksum ---
{
  const report = evaluateDocumentValidation({
    documentType: "aadhaar",
    identifyConfidence: 0.9,
    extractedData: {
      aadhaarNumber: "1234 5678 9012",
      name: "RAMESH KUMAR",
    },
    fieldConfidence: { aadhaarNumber: 0.9, name: 0.9 },
    extractionOk: true,
    idChecksumFailed: true,
  });
  assert(
    report.status === "INVALID" || report.status === "NEEDS_REVIEW",
    `bad Aadhaar → INVALID/NEEDS_REVIEW (got ${report.status})`,
  );
  assert(!validationStatusToIsValid(report.status), "non-VALID is not isValid");
}

// --- Missing fields → NEEDS_REVIEW ---
{
  const report = evaluateDocumentValidation({
    documentType: "pan",
    identifyConfidence: 0.88,
    extractedData: { panNumber: "ABCDE1234F" },
    fieldConfidence: { panNumber: 0.9 },
    extractionOk: true,
  });
  assert(report.status === "NEEDS_REVIEW", `PAN missing name → NEEDS_REVIEW (got ${report.status})`);
  assert(
    report.fieldResults.some((f) => f.field === "name" && f.status === "missing"),
    "name marked missing",
  );
}

// --- Processing failed ---
{
  const report = evaluateDocumentValidation({
    documentType: "aadhaar",
    identifyConfidence: 0.1,
    processingError: "File corrupted / unreadable",
  });
  assert(report.status === "PROCESSING_FAILED", "processing error → PROCESSING_FAILED");
}

// --- Uncertain identify ---
{
  const report = evaluateDocumentValidation({
    documentType: "other",
    identifyConfidence: 0.2,
    extractionOk: true,
    extractedData: {},
  });
  assert(report.status === "NEEDS_REVIEW", "unknown type → NEEDS_REVIEW (no guess)");
  assert(!report.identification.accepted, "identification not accepted");
}

// --- Forensic escalate to review ---
{
  const report = evaluateDocumentValidation({
    documentType: "pan",
    identifyConfidence: 0.9,
    extractedData: {
      panNumber: "ABCDE1234F",
      name: "TEST USER",
    },
    fieldConfidence: { panNumber: 0.95, name: 0.9 },
    extractionOk: true,
    forensicVerdict: "SUSPICIOUS",
  });
  assert(report.status === "NEEDS_REVIEW", "suspicious forensics → NEEDS_REVIEW (not silent VALID)");
}

// --- Cross-type: Udyam must not validate as Aadhaar schema ---
{
  const report = evaluateDocumentValidation({
    documentType: "aadhaar",
    identifyConfidence: 0.95,
    extractedData: {
      aadhaarNumber: "UDYAM-MH-04-0294318",
      name: "SWARAJYA RESEARCH",
    },
    fieldConfidence: { aadhaarNumber: 0.9, name: 0.9 },
    ocrText: UDYAM_OCR,
    extractionOk: true,
  });
  assert(
    report.status === "INVALID" ||
      report.fieldResults.some((f) => f.field === "aadhaarNumber" && f.status === "failed"),
    "Udyam number must fail Aadhaar field validation",
  );
}

if (failed > 0) {
  console.error(`\n${failed} assertion(s) failed`);
  process.exit(1);
}
console.log("\nAll banking validation smoke checks passed.");

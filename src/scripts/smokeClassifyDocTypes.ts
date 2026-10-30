/**
 * Smoke tests for document-type classification (Udyam vs Aadhaar and peers).
 * Run: npx ts-node --transpile-only src/scripts/smokeClassifyDocTypes.ts
 */
import {
  classifyFromOcrText,
  correctMisclassifiedType,
  fuseDocumentTypes,
  hasStrongUdyamSignals,
  toInternalDocumentType,
  type ClassifiedDocument,
} from "../services/documentClassify.service";

const UDYAM_OCR = `
UDYAM REGISTRATION CERTIFICATE
GOVERNMENT OF INDIA
MINISTRY OF MICRO, SMALL AND MEDIUM ENTERPRISES
UDYAM REGISTRATION NUMBER UDYAM-MH-04-0294318
NAME OF ENTERPRISE SWARAJYA RESEARCH AND CONSULTANCY PRIVATE LIMITED
TYPE OF ENTERPRISE Classification Year 2026-27 Enterprise Type Micro
OFFICIAL ADDRESS OF ENTERPRISE Flat N-9-L60/04 CIDCO Aurangabad MAHARASHTRA
Mobile 8485018690 Email swarajyaresearchandconsultancy@gmail.com
NATIONAL INDUSTRY CLASSIFICATION CODE(S)
NIC 2 Digit 62 Computer programming NIC 4 Digit 6209 NIC 5 Digit 62099
DATE OF UDYAM REGISTRATION 21/04/2026
https://udyamregistration.gov.in
This is a computer generated statement, no signature required.
`.trim();

const UDYOG_AADHAAR_OCR = `
UDYOG AADHAAR REGISTRATION CERTIFICATE
Ministry of Micro, Small and Medium Enterprises
Udyog Aadhaar Number: MH04A0001234
Name of Enterprise: Sample Trading Company
Type of Organisation: Proprietary
`.trim();

const AADHAAR_OCR = `
Unique Identification Authority of India
Government of India
आधार
UIDAI
Name: RAMESH KUMAR
DOB: 01/01/1990
Male
1234 5678 9012
VID: 1234 5678 9012 3456
`.trim();

const PAN_OCR = `
INCOME TAX DEPARTMENT
GOVERNMENT OF INDIA
Permanent Account Number Card
ABCDE1234F
Name: RAMESH KUMAR
`.trim();

type Case = {
  name: string;
  run: () => void;
};

let failed = 0;

function assert(cond: boolean, msg: string) {
  if (!cond) {
    failed += 1;
    console.error(`FAIL: ${msg}`);
  } else {
    console.log(`OK:   ${msg}`);
  }
}

function local(ocr: string): ClassifiedDocument {
  return classifyFromOcrText(ocr);
}

const cases: Case[] = [
  {
    name: "udyam strong signals",
    run: () => {
      assert(hasStrongUdyamSignals(UDYAM_OCR), "Udyam OCR has strong signals");
      assert(
        !hasStrongUdyamSignals(AADHAAR_OCR),
        "Aadhaar OCR must not have Udyam signals",
      );
    },
  },
  {
    name: "match order Udyog Aadhaar → udyam",
    run: () => {
      assert(
        toInternalDocumentType("Udyog Aadhaar") === "udyam certificate",
        'toInternal("Udyog Aadhaar") → udyam certificate',
      );
      assert(
        toInternalDocumentType("Udyam Certificate") === "udyam certificate",
        'toInternal("Udyam Certificate") → udyam certificate',
      );
      assert(
        toInternalDocumentType("Aadhaar") === "aadhaar",
        'toInternal("Aadhaar") → aadhaar',
      );
      assert(
        toInternalDocumentType("Aadhaar Card") === "aadhaar",
        'toInternal("Aadhaar Card") → aadhaar',
      );
    },
  },
  {
    name: "local classify Udyam vs Aadhaar",
    run: () => {
      const u = local(UDYAM_OCR);
      assert(
        toInternalDocumentType(u.documentType) === "udyam certificate",
        `local Udyam → ${u.documentType} (conf=${u.confidence.toFixed(2)})`,
      );
      const ua = local(UDYOG_AADHAAR_OCR);
      assert(
        toInternalDocumentType(ua.documentType) === "udyam certificate",
        `local Udyog Aadhaar → ${ua.documentType}`,
      );
      const a = local(AADHAAR_OCR);
      assert(
        toInternalDocumentType(a.documentType) === "aadhaar",
        `local Aadhaar → ${a.documentType}`,
      );
      const p = local(PAN_OCR);
      assert(
        toInternalDocumentType(p.documentType) === "pan",
        `local PAN → ${p.documentType}`,
      );
    },
  },
  {
    name: "AI Aadhaar mislabel corrected by OCR",
    run: () => {
      const corrected = correctMisclassifiedType("Aadhaar", UDYAM_OCR);
      assert(
        toInternalDocumentType(corrected) === "udyam certificate",
        `correctMisclassifiedType(Aadhaar, udyamOCR) → ${corrected}`,
      );
    },
  },
  {
    name: "fuse: local Udyam beats AI Aadhaar",
    run: () => {
      const loc = local(UDYAM_OCR);
      const fused = fuseDocumentTypes(
        { documentType: "Aadhaar", confidence: 0.95 },
        loc,
      );
      assert(
        toInternalDocumentType(fused.documentType) === "udyam certificate",
        `fuse(AI=Aadhaar, local=Udyam) → ${fused.documentType} [${fused.source}]`,
      );
    },
  },
  {
    name: "fuse: OCR Udyam beats AI Aadhaar even if local weak type",
    run: () => {
      const weakLocal: ClassifiedDocument = {
        documentType: "Other",
        confidence: 0.2,
        evidence: ["no_strong_signal"],
        ocrText: UDYAM_OCR.toLowerCase(),
        extractedData: {},
      };
      const fused = fuseDocumentTypes(
        { documentType: "Aadhaar", confidence: 0.92 },
        weakLocal,
      );
      assert(
        toInternalDocumentType(fused.documentType) === "udyam certificate",
        `fuse(AI=Aadhaar, weak local + udyam OCR) → ${fused.documentType} [${fused.source}]`,
      );
    },
  },
  {
    name: "negative: Aadhaar must stay Aadhaar",
    run: () => {
      const loc = local(AADHAAR_OCR);
      const fused = fuseDocumentTypes(
        { documentType: "Aadhaar", confidence: 0.9 },
        loc,
      );
      assert(
        toInternalDocumentType(fused.documentType) === "aadhaar",
        `fuse Aadhaar stays aadhaar → ${fused.documentType}`,
      );
      const corrected = correctMisclassifiedType("Aadhaar", AADHAAR_OCR);
      assert(
        toInternalDocumentType(corrected) === "aadhaar",
        "correctMisclassifiedType does not flip real Aadhaar",
      );
    },
  },
];

console.log("=== Document classify smoke ===\n");
for (const c of cases) {
  console.log(`-- ${c.name}`);
  c.run();
  console.log("");
}

if (failed > 0) {
  console.error(`\n${failed} assertion(s) failed`);
  process.exit(1);
}
console.log("All classification smoke checks passed.");

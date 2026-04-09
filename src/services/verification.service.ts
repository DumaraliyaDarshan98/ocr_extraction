import { validateAadhaar } from "../validators/aadhaar.validator";
import { validatePAN } from "../validators/pan.validator";
import { validatePassport } from "../validators/passport.validator";
import { validateDrivingLicense } from "../validators/drivingLicense.validator";
import { detectKeywords } from "../utils/keyword.util";
import { scanQrCode } from "../utils/qr.util";
import { getImageMetadata } from "../utils/metadata.util";
import { analyzeDocumentAI, AiAnalysisResult } from "./aiVerification.service";
import { extractStructuredDataFromDocument } from "./geminiExtraction.service";
import {
  hasTriggersForDocumentType,
  loadTriggerConfig,
} from "./triggerConfig.service";
import { runValidationEngine } from "../validation/validationEngine";
import type { ValidationEngineResult } from "../validation/types";

export interface VerificationResult {
  documentDetected: boolean;
  documentType: string | null;
  extractedNumber?: string | undefined;
  numberValid: boolean;
  qrDetected: boolean;
  documentValid: boolean;
  aiAnalysis?: AiAnalysisResult | null;
  extractedText: string;
  confidenceScore: number;
  metadata: any;
  reason?: string | undefined;
  /** Present when config-driven validation runs (Gemini JSON + trigger rules). */
  fieldValidation?: ValidationEngineResult | null;
  extractedData?: Record<string, unknown> | null;
}

function pickPrimaryIdentifier(
  normalizedType: string,
  data: Record<string, unknown>
): string | undefined {
  const keys =
    normalizedType === "pan"
      ? ["pan", "panNumber", "panNo"]
      : normalizedType === "aadhaar"
        ? ["aadhaar", "aadhar", "uid", "aadhaarNumber"]
        : normalizedType === "passport"
          ? ["passport", "passportNo", "passportNumber"]
          : ["license", "licenseNumber", "dlNumber", "drivingLicense"];

  for (const k of keys) {
    const v = data[k];
    if (v !== null && v !== undefined && String(v).trim() !== "") {
      return String(v).trim();
    }
  }
  const first = Object.values(data).find(
    (v) => v !== null && v !== undefined && String(v).trim() !== ""
  );
  return first !== undefined ? String(first).trim() : undefined;
}

export const verifyDocumentService = async (
  type: string,
  text: string,
  imagePath: string
): Promise<VerificationResult> => {
  try {
    const normalizedType = (type || "").toLowerCase();

    const keywordMatch = detectKeywords(normalizedType, text);

    const qrResult = await scanQrCode(imagePath);
    const metadata = await getImageMetadata(imagePath);
    const aiAnalysis = await analyzeDocumentAI(imagePath);

    let triggerConfig;
    try {
      triggerConfig = loadTriggerConfig();
    } catch {
      triggerConfig = { version: 1, triggers: [] };
    }

    const useDynamicValidation = hasTriggersForDocumentType(
      normalizedType,
      triggerConfig
    );

    if (useDynamicValidation) {
      const extracted = await extractStructuredDataFromDocument(
        imagePath,
        normalizedType
      );

      if (!extracted) {
        return {
          documentDetected: keywordMatch,
          documentType: normalizedType,
          numberValid: false,
          qrDetected: qrResult.found,
          documentValid: false,
          aiAnalysis,
          extractedText: text,
          confidenceScore: 0,
          metadata,
          reason: "Structured extraction unavailable (check GEMINI_API_KEY)",
          fieldValidation: null,
          extractedData: null,
        };
      }

      const fieldValidation = runValidationEngine(
        normalizedType,
        extracted.data,
        triggerConfig
      );

      const extractedNumber = pickPrimaryIdentifier(
        normalizedType,
        extracted.data
      );

      let confidenceScore = 0;
      if (keywordMatch) {
        confidenceScore += 30;
      }
      if (fieldValidation.valid) {
        confidenceScore += 30;
      }
      if (qrResult.found) {
        confidenceScore += 20;
      }
      if (aiAnalysis && typeof aiAnalysis.authenticityScore === "number") {
        const normalized = Math.max(
          0,
          Math.min(100, aiAnalysis.authenticityScore)
        );
        confidenceScore += (normalized / 100) * 20;
      }

      const documentDetected = keywordMatch;
      const documentValid = documentDetected && fieldValidation.valid;

      return {
        documentDetected,
        documentType: normalizedType,
        extractedNumber,
        numberValid: fieldValidation.valid,
        qrDetected: qrResult.found,
        documentValid,
        aiAnalysis,
        extractedText: text,
        confidenceScore,
        metadata,
        reason: keywordMatch ? undefined : "Document keywords not found",
        fieldValidation,
        extractedData: extracted.data,
      };
    }

    let extractedNumber: string | undefined;
    let numberValid = false;

    switch (normalizedType) {
      case "aadhaar": {
        const result = validateAadhaar(text);
        extractedNumber = result.number;
        numberValid = !!result.valid;
        break;
      }
      case "pan": {
        const result = validatePAN(text);
        extractedNumber = result.number;
        numberValid = !!result.valid;
        break;
      }
      case "passport": {
        const result = validatePassport(text);
        extractedNumber = result.number;
        numberValid = !!result.valid;
        break;
      }
      case "driving license":
      case "driving_license": {
        const result = validateDrivingLicense(text);
        extractedNumber = result.number;
        numberValid = !!result.valid;
        break;
      }
      default:
        return {
          documentDetected: false,
          documentType: null,
          numberValid: false,
          qrDetected: qrResult.found,
          documentValid: false,
          aiAnalysis,
          extractedText: text,
          confidenceScore: 0,
          metadata,
          reason: "Document type not supported",
        };
    }

    let confidenceScore = 0;

    if (keywordMatch) {
      confidenceScore += 30;
    }

    if (numberValid) {
      confidenceScore += 30;
    }

    if (qrResult.found) {
      confidenceScore += 20;
    }

    if (aiAnalysis && typeof aiAnalysis.authenticityScore === "number") {
      const normalized = Math.max(
        0,
        Math.min(100, aiAnalysis.authenticityScore)
      );
      confidenceScore += (normalized / 100) * 20;
    }

    const documentDetected = keywordMatch;
    const documentValid = documentDetected && numberValid;

    return {
      documentDetected,
      documentType: normalizedType,
      extractedNumber,
      numberValid,
      qrDetected: qrResult.found,
      documentValid,
      aiAnalysis,
      extractedText: text,
      confidenceScore,
      metadata,
      reason: keywordMatch ? undefined : "Document keywords not found",
    };
  } catch (error) {
    console.error("Error verifying document:", error);
    return {
      documentDetected: false,
      documentType: null,
      numberValid: false,
      qrDetected: false,
      documentValid: false,
      aiAnalysis: null,
      extractedText: text,
      confidenceScore: 0,
      metadata: null,
      reason: "Error verifying document",
    };
  }
};

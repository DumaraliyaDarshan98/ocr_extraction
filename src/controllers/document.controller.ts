import { Request, Response } from "express";
import { runKycVerification } from "../services/kycVerification.service";
import { loadTriggerConfig } from "../services/triggerConfig.service";
import { runValidationEngine } from "../validation/validationEngine";
import {
  extractStructuredDataFromDocument,
  identifyDocumentTypeFromFile,
} from "../services/geminiExtraction.service";
import { extractText } from "../services/ocr.service";
import type { KycApiResponse } from "../types/kyc.types";

type MulterFiles = {
  file?: Express.Multer.File[];
  selfie?: Express.Multer.File[];
};

function badRequest(res: Response, message: string): Response {
  const body: KycApiResponse = {
    success: false,
    documentType: null,
    isValid: false,
    extractedData: {},
    confidence: {},
    faceMatchScore: null,
    nameMatchScore: null,
    checks: [],
    triggerResults: [],
    errors: [{ field: "request", message }],
    message,
  };
  return res.status(400).json(body);
}

export const verifyDocument = async (req: Request, res: Response) => {
  const started = Date.now();
  try {
    const files = req.files as MulterFiles | undefined;
    const primaryFile =
      files?.file?.[0] ??
      (req as Express.Request & { file?: Express.Multer.File }).file;
    const filePath = primaryFile?.path;

    const documentType = String(req.body?.documentType ?? "");
    const expectedName =
      req.body?.expectedName !== undefined
        ? String(req.body.expectedName)
        : undefined;
    const requireDob =
      String(req.body?.requireDob ?? "").toLowerCase() === "true";
    const selfiePath = files?.selfie?.[0]?.path;
    const useRcuTriggers =
      String(req.body?.useRcuTriggers ?? "").toLowerCase() === "true";

    console.log(
      `[OCR:VERIFY] start file="${primaryFile?.originalname ?? "unknown"}" path=${filePath ?? "(missing)"} mime=${primaryFile?.mimetype ?? "unknown"} size=${primaryFile?.size ?? 0} documentType="${documentType}" useRcuTriggers=${useRcuTriggers}`
    );

    let rcuTriggers: Array<{
      code: string;
      text: string;
      risk?: string;
      section?: string | null;
    }> = [];
    if (req.body?.triggers) {
      try {
        const parsed =
          typeof req.body.triggers === "string"
            ? JSON.parse(req.body.triggers)
            : req.body.triggers;
        if (Array.isArray(parsed)) {
          rcuTriggers = parsed
            .filter((t) => t && typeof t === "object" && t.text)
            .map((t) => {
              const item: {
                code: string;
                text: string;
                risk?: string;
                section?: string | null;
              } = {
                code: String(t.code ?? ""),
                text: String(t.text ?? ""),
              };
              if (t.risk) item.risk = String(t.risk);
              if (t.section) item.section = String(t.section);
              return item;
            });
        }
      } catch (parseErr) {
        console.warn("[OCR:VERIFY] triggers JSON parse failed", parseErr);
        rcuTriggers = [];
      }
    }

    if (!filePath) {
      console.error("[OCR:VERIFY] FAIL File missing (field: file)");
      return badRequest(res, "File missing (field: file)");
    }
    if (!documentType) {
      console.error("[OCR:VERIFY] FAIL documentType is required");
      return badRequest(res, "documentType is required");
    }

    console.log(`[OCR:VERIFY] triggers loaded count=${rcuTriggers.length}`);

    const result = await runKycVerification({
      documentType,
      documentPath: filePath,
      documentMimeType: primaryFile?.mimetype,
      selfiePath,
      expectedName,
      requireDob,
      ...(useRcuTriggers || rcuTriggers.length ? { rcuTriggers } : {}),
    });

    console.log(
      `[OCR:VERIFY] OK documentType="${documentType}" success=${result.success} isValid=${result.isValid} triggers=${result.triggerResults?.length ?? 0} ms=${Date.now() - started}`
    );

    res.json(result);
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    const errStack = error instanceof Error ? error.stack : undefined;
    console.error(`[OCR:VERIFY] FAIL ms=${Date.now() - started} error="${errMsg}"`, errStack);
    res.status(500).json({
      success: false,
      documentType: null,
      isValid: false,
      extractedData: {},
      confidence: {},
      faceMatchScore: null,
      nameMatchScore: null,
      checks: [],
      triggerResults: [],
      errors: [{ field: "server", message: errMsg || "Verification failed" }],
      message: errMsg || "Verification failed",
    });
  }
};

/**
 * Config-only validation: POST JSON body { documentType, extractedData }.
 */
export const validateExtractedData = async (req: Request, res: Response) => {
  try {
    const documentType = String(req.body?.documentType ?? "");
    const extractedData = req.body?.extractedData;

    if (
      !documentType ||
      typeof extractedData !== "object" ||
      extractedData === null
    ) {
      return res.status(400).json({
        message: "documentType and extractedData (object) are required",
      });
    }

    const config = loadTriggerConfig();
    const result = runValidationEngine(
      documentType,
      extractedData as Record<string, unknown>,
      config
    );
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: "Validation failed" });
  }
};

interface SimpleExtractionApiResponse {
  success: boolean;
  documentType: string | null;
  extractedText: string;
  extractedData: Record<string, unknown>;
  confidence: Record<string, number>;
  message: string;
}

/**
 * Classify document type only (no full OCR / RCU).
 * POST multipart field: file
 */
export const identifyDocument = async (req: Request, res: Response) => {
  const started = Date.now();
  try {
    const file = (req as Express.Request & { file?: Express.Multer.File }).file;
    const filePath = file?.path;

    console.log(
      `[OCR:IDENTIFY] start file="${file?.originalname ?? "unknown"}" path=${filePath ?? "(missing)"} mime=${file?.mimetype ?? "unknown"} size=${file?.size ?? 0}`
    );

    if (!filePath) {
      console.error("[OCR:IDENTIFY] FAIL File missing (field: file)");
      return res.status(400).json({
        success: false,
        documentType: null,
        confidence: null,
        message: "File missing (field: file)",
      });
    }

    const result = await identifyDocumentTypeFromFile(filePath, file?.mimetype);
    if (!result) {
      console.warn(
        `[OCR:IDENTIFY] low confidence → Other file="${file?.originalname}" ms=${Date.now() - started}`
      );
      return res.status(200).json({
        success: true,
        documentType: "Other",
        confidence: 0,
        message: "Could not confidently identify document; defaulted to Other",
      });
    }

    console.log(
      `[OCR:IDENTIFY] OK file="${file?.originalname}" documentType="${result.documentType}" confidence=${result.confidence} ms=${Date.now() - started}`
    );

    return res.json({
      success: true,
      documentType: result.documentType,
      confidence: result.confidence,
      message: "Document identified",
    });
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    const errStack = error instanceof Error ? error.stack : undefined;
    console.error(`[OCR:IDENTIFY] FAIL ms=${Date.now() - started} error="${errMsg}"`, errStack);
    return res.status(500).json({
      success: false,
      documentType: null,
      confidence: null,
      message: errMsg || "Document identification failed",
    });
  }
};

export const extractDocumentSimple = async (req: Request, res: Response) => {
  try {
    const file = (req as Express.Request & { file?: Express.Multer.File }).file;
    const filePath = file?.path;
    const documentType = String(req.body?.documentType ?? "");

    if (!filePath) {
      const body: SimpleExtractionApiResponse = {
        success: false,
        documentType: null,
        extractedText: "",
        extractedData: {},
        confidence: {},
        message: "File missing (field: file)",
      };
      return res.status(400).json(body);
    }

    if (!documentType) {
      const body: SimpleExtractionApiResponse = {
        success: false,
        documentType: null,
        extractedText: "",
        extractedData: {},
        confidence: {},
        message: "documentType is required",
      };
      return res.status(400).json(body);
    }

    console.log("filePath", filePath);
    console.log("documentType", documentType);
    console.log("file?.mimetype", file?.mimetype);
    const structured = await extractStructuredDataFromDocument(
      filePath,
      documentType,
      file?.mimetype
    );

    console.log("structured", structured);

    if (structured) {
      const body: SimpleExtractionApiResponse = {
        success: true,
        documentType,
        extractedText: structured.rawText,
        extractedData: structured.data,
        confidence: structured.fieldConfidence,
        message: "Extraction completed",
      };
      return res.json(body);
    }

    const fallbackText = await extractText(filePath, file?.mimetype);
    const body: SimpleExtractionApiResponse = {
      success: fallbackText.trim().length > 0,
      documentType,
      extractedText: fallbackText,
      extractedData: {},
      confidence: {},
      message:
        fallbackText.trim().length > 0
          ? "Extraction completed"
          : "Could not extract text from document",
    };
    return res.json(body);
  } catch {
    const body: SimpleExtractionApiResponse = {
      success: false,
      documentType: null,
      extractedText: "",
      extractedData: {},
      confidence: {},
      message: "Extraction failed",
    };
    return res.status(500).json(body);
  }
};

import { analyzeFileIntegrity, type ForensicSignal } from "./fileIntegrity.service";
import { analyzePdfMetadata, type PdfMetadata } from "./pdfMetadata.service";
import { analyzeMathRules } from "./mathValidation.service";
import { analyzeImageForensics } from "./imageForensics.service";
import { analyzeDocForensics } from "./docForensics.service";
import { analyzeZipForensics } from "./zipForensics.service";
import { analyzeVisualTamperFromExtracted } from "./visualTamper.service";
import type { ForensicSummary } from "./forensicFusion.service";
import type { TriggerResultItem } from "../../types/kyc.types";
import {
  applyForensicConfigs,
  type ForensicConfigItem,
} from "./applyForensicConfigs";
import {
  detectForensicFileCategory,
  type ForensicFileCategory,
} from "./detectFileCategory";

export type DocumentForensicResult = {
  fileHash: string;
  fileSizeBytes: number;
  fileCategory: ForensicFileCategory | null;
  pdfMetadata: PdfMetadata | null;
  forensicSignals: ForensicSignal[];
  forensicSummary: ForensicSummary;
};

/**
 * Run forensics for the detected upload file category:
 * - PDF → integrity + PDF metadata/structure + math + visual tamper
 * - IMAGE → integrity + EXIF/editor + ELA + math + visual tamper
 * - DOC → office integrity + OOXML revision/tracked changes + visual tamper
 * - ZIP → archive integrity + suspicious entries + visual tamper
 *
 * Optional admin configs (already filtered by category) overlay severity/score/title.
 */
export async function runDocumentForensics(options: {
  filePath: string;
  mimeType?: string;
  originalFileName?: string;
  documentType: string;
  extractedData?: Record<string, unknown> | null;
  triggerResults?: TriggerResultItem[];
  forensicConfigs?: ForensicConfigItem[] | null;
  fileCategory?: ForensicFileCategory | null;
}): Promise<DocumentForensicResult> {
  const fileCategory =
    options.fileCategory ??
    detectForensicFileCategory(
      options.originalFileName || options.filePath,
      options.mimeType
    );

  const signals: ForensicSignal[] = [];
  let fileHash = "";
  let fileSizeBytes = 0;
  let pdfMetadata: PdfMetadata | null = null;

  console.log(
    `[OCR:FORENSICS] start category=${fileCategory ?? "unknown"} type="${options.documentType}" file="${options.originalFileName || options.filePath}"`
  );

  if (fileCategory === "DOC") {
    const doc = analyzeDocForensics(options.filePath, options.originalFileName);
    fileHash = doc.sha256;
    fileSizeBytes = doc.sizeBytes;
    signals.push(...doc.signals);
    signals.push(
      ...analyzeMathRules(options.documentType, options.extractedData ?? null)
    );
  } else if (fileCategory === "ZIP") {
    const zip = analyzeZipForensics(options.filePath, options.originalFileName);
    fileHash = zip.sha256;
    fileSizeBytes = zip.sizeBytes;
    signals.push(...zip.signals);
  } else {
    const integrity = analyzeFileIntegrity(
      options.filePath,
      options.mimeType,
      options.originalFileName
    );
    fileHash = integrity.sha256;
    fileSizeBytes = integrity.sizeBytes;
    signals.push(...integrity.signals);

    if (fileCategory === "PDF") {
      const isPdf =
        integrity.magic === "pdf" ||
        (options.mimeType || "").includes("pdf") ||
        (options.originalFileName || options.filePath).toLowerCase().endsWith(".pdf");
      if (isPdf) {
        const pdf = analyzePdfMetadata(options.filePath);
        pdfMetadata = pdf.metadata;
        signals.push(...pdf.signals);
      }
      signals.push(
        ...analyzeMathRules(options.documentType, options.extractedData ?? null)
      );
    } else if (fileCategory === "IMAGE") {
      signals.push(
        ...(await analyzeImageForensics(
          options.filePath,
          options.originalFileName,
          options.mimeType
        ))
      );
      signals.push(
        ...analyzeMathRules(options.documentType, options.extractedData ?? null)
      );
    } else {
      const looksPdf =
        integrity.magic === "pdf" ||
        (options.mimeType || "").includes("pdf") ||
        (options.originalFileName || options.filePath).toLowerCase().endsWith(".pdf");
      if (looksPdf) {
        const pdf = analyzePdfMetadata(options.filePath);
        pdfMetadata = pdf.metadata;
        signals.push(...pdf.signals);
      } else {
        // Unknown binary that might still be an image
        try {
          signals.push(
            ...(await analyzeImageForensics(
              options.filePath,
              options.originalFileName,
              options.mimeType
            ))
          );
        } catch {
          /* ignore */
        }
      }
      signals.push(
        ...analyzeMathRules(options.documentType, options.extractedData ?? null)
      );
    }
  }

  // Universal: Gemini/visual extraction tamper flags (marks, whiteouts, text removal)
  signals.push(...analyzeVisualTamperFromExtracted(options.extractedData ?? null));

  const applied = applyForensicConfigs(
    signals,
    options.forensicConfigs,
    options.documentType,
    options.triggerResults ?? []
  );

  console.log(
    `[OCR:FORENSICS] done category=${fileCategory ?? "unknown"} verdict=${applied.forensicSummary.verdict} score=${applied.forensicSummary.riskScore} failedSignals=${applied.forensicSummary.failedSignalCount}`
  );

  return {
    fileHash,
    fileSizeBytes,
    fileCategory,
    pdfMetadata,
    forensicSignals: applied.signals,
    forensicSummary: applied.forensicSummary,
  };
}

export type {
  ForensicSignal,
  ForensicSummary,
  PdfMetadata,
  ForensicConfigItem,
  ForensicFileCategory,
};

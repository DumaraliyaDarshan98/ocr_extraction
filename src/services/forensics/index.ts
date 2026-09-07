import { analyzeFileIntegrity, type ForensicSignal } from "./fileIntegrity.service";
import { analyzePdfMetadata, type PdfMetadata } from "./pdfMetadata.service";
import { analyzeMathRules } from "./mathValidation.service";
import { analyzeImageForensics } from "./imageForensics.service";
import { analyzeDocForensics } from "./docForensics.service";
import { analyzeZipForensics } from "./zipForensics.service";
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
 * Run forensics for the detected upload file category only:
 * - PDF → integrity + PDF metadata + math
 * - IMAGE → integrity + image checks + math
 * - DOC → office document checks
 * - ZIP → archive checks
 *
 * Optional admin configs (already filtered by category) overlay severity/score/title.
 */
export function runDocumentForensics(options: {
  filePath: string;
  mimeType?: string;
  originalFileName?: string;
  documentType: string;
  extractedData?: Record<string, unknown> | null;
  triggerResults?: TriggerResultItem[];
  forensicConfigs?: ForensicConfigItem[] | null;
  fileCategory?: ForensicFileCategory | null;
}): DocumentForensicResult {
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

  if (fileCategory === "DOC") {
    const doc = analyzeDocForensics(options.filePath);
    fileHash = doc.sha256;
    fileSizeBytes = doc.sizeBytes;
    signals.push(...doc.signals);
  } else if (fileCategory === "ZIP") {
    const zip = analyzeZipForensics(options.filePath);
    fileHash = zip.sha256;
    fileSizeBytes = zip.sizeBytes;
    signals.push(...zip.signals);
  } else {
    // PDF / IMAGE / unknown → shared integrity first
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
        ...analyzeImageForensics(
          options.filePath,
          options.originalFileName,
          options.mimeType
        )
      );
      signals.push(
        ...analyzeMathRules(options.documentType, options.extractedData ?? null)
      );
    } else {
      // Unknown type: integrity only (backward-compatible defaults)
      const looksPdf =
        integrity.magic === "pdf" ||
        (options.mimeType || "").includes("pdf") ||
        (options.originalFileName || options.filePath).toLowerCase().endsWith(".pdf");
      if (looksPdf) {
        const pdf = analyzePdfMetadata(options.filePath);
        pdfMetadata = pdf.metadata;
        signals.push(...pdf.signals);
      }
      signals.push(
        ...analyzeMathRules(options.documentType, options.extractedData ?? null)
      );
    }
  }

  const applied = applyForensicConfigs(
    signals,
    options.forensicConfigs,
    options.documentType,
    options.triggerResults ?? []
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

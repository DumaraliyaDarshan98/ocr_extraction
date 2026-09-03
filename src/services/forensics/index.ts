import { analyzeFileIntegrity, type ForensicSignal } from "./fileIntegrity.service";
import { analyzePdfMetadata, type PdfMetadata } from "./pdfMetadata.service";
import { analyzeMathRules } from "./mathValidation.service";
import { fuseForensicVerdict, type ForensicSummary } from "./forensicFusion.service";
import type { TriggerResultItem } from "../../types/kyc.types";

export type DocumentForensicResult = {
  fileHash: string;
  fileSizeBytes: number;
  pdfMetadata: PdfMetadata | null;
  forensicSignals: ForensicSignal[];
  forensicSummary: ForensicSummary;
};

/**
 * Phase-1 forensic pack: hash + PDF metadata + math rules + fused verdict.
 */
export function runDocumentForensics(options: {
  filePath: string;
  mimeType?: string;
  documentType: string;
  extractedData?: Record<string, unknown> | null;
  triggerResults?: TriggerResultItem[];
}): DocumentForensicResult {
  const integrity = analyzeFileIntegrity(options.filePath, options.mimeType);
  const signals: ForensicSignal[] = [...integrity.signals];

  let pdfMetadata: PdfMetadata | null = null;
  const isPdf =
    integrity.magic === "pdf" ||
    (options.mimeType || "").includes("pdf") ||
    options.filePath.toLowerCase().endsWith(".pdf");

  if (isPdf) {
    const pdf = analyzePdfMetadata(options.filePath);
    pdfMetadata = pdf.metadata;
    signals.push(...pdf.signals);
  }

  signals.push(
    ...analyzeMathRules(options.documentType, options.extractedData ?? null)
  );

  const forensicSummary = fuseForensicVerdict(
    signals,
    options.triggerResults ?? []
  );

  return {
    fileHash: integrity.sha256,
    fileSizeBytes: integrity.sizeBytes,
    pdfMetadata,
    forensicSignals: signals,
    forensicSummary,
  };
}

export type { ForensicSignal, ForensicSummary, PdfMetadata };

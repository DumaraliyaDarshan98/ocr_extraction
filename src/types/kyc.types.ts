export interface KycError {
  field: string;
  message: string;
}

export interface KycCheck {
  id: string;
  label: string;
  source: "document" | "user_input" | "system";
  status: "passed" | "failed" | "skipped";
  details?: string;
}

export interface TriggerResultItem {
  field: string;
  triggerType: string;
  status: "passed" | "failed" | "skipped";
  message: string;
  text?: string;
}

export interface ForensicSignalItem {
  code: string;
  threatCode: string;
  severity: "low" | "medium" | "high";
  score: number;
  status: "passed" | "failed" | "info" | "skipped";
  title: string;
  description: string;
  evidence?: Record<string, unknown>;
}

export interface ForensicSummaryItem {
  riskScore: number;
  verdict: "GENUINE" | "LIKELY_GENUINE" | "SUSPICIOUS" | "TEMP" | "MANUAL_REVIEW";
  verdictLabel: string;
  reasons: string[];
  failedSignalCount: number;
  failedTriggerCount: number;
}

/** Banking-grade per-document validation status (separate from case workflow). */
export type DocumentValidationStatus =
  | "VALID"
  | "NEEDS_REVIEW"
  | "INVALID"
  | "PROCESSING_FAILED";

export interface DocumentFieldValidationItem {
  field: string;
  status: "passed" | "failed" | "missing" | "skipped" | "low_confidence";
  severity: "error" | "warning" | "info";
  message: string;
  valuePreview?: string | null;
}

export interface DocumentValidationReportPayload {
  status: DocumentValidationStatus;
  statusLabel: string;
  reasons: string[];
  fieldResults: DocumentFieldValidationItem[];
  identification: {
    documentType: string;
    confidence: number;
    accepted: boolean;
    uncertain: boolean;
  };
  authenticityNote: string;
  trace: {
    sourceFile?: string | null;
    identifySource?: string | null;
    extractionOk: boolean;
    requiredFieldCount: number;
    failedFieldCount: number;
    missingFieldCount: number;
    lowConfidenceFieldCount: number;
  };
}

export interface KycApiResponse {
  /** False when HTTP 400 or 500; true when the handler completed normally */
  success: boolean;
  documentType: string | null;
  isValid: boolean;
  extractedData: Record<string, unknown>;
  confidence: Record<string, number>;
  faceMatchScore: number | null;
  nameMatchScore: number | null;
  checks: KycCheck[];
  triggerResults: TriggerResultItem[];
  errors: KycError[];
  message: string;
  /** Banking-grade validation (identify ≠ extract ≠ validate ≠ authenticity). */
  validationStatus?: DocumentValidationStatus;
  validationStatusLabel?: string;
  validationReport?: DocumentValidationReportPayload | null;
  identifyConfidence?: number | null;
  /** Phase-1 forensics */
  fileHash?: string | null;
  fileSizeBytes?: number | null;
  pdfMetadata?: Record<string, unknown> | null;
  forensicSignals?: ForensicSignalItem[];
  forensicSummary?: ForensicSummaryItem | null;
}

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
  status: "passed" | "failed";
  message: string;
  text?: string;
}

export interface ForensicSignalItem {
  code: string;
  threatCode: string;
  severity: "low" | "medium" | "high";
  score: number;
  status: "passed" | "failed" | "info";
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
  /** Phase-1 forensics */
  fileHash?: string | null;
  fileSizeBytes?: number | null;
  pdfMetadata?: Record<string, unknown> | null;
  forensicSignals?: ForensicSignalItem[];
  forensicSummary?: ForensicSummaryItem | null;
}

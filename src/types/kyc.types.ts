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
}

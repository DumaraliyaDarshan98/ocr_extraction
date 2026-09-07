import type { ForensicSignal } from "./fileIntegrity.service";
import type { TriggerResultItem } from "../../types/kyc.types";

export type ForensicVerdict =
  | "GENUINE"
  | "LIKELY_GENUINE"
  | "SUSPICIOUS"
  | "TEMP"
  | "MANUAL_REVIEW";

export type ForensicSummary = {
  riskScore: number;
  verdict: ForensicVerdict;
  verdictLabel: string;
  reasons: string[];
  failedSignalCount: number;
  failedTriggerCount: number;
};

function riskWeight(triggerType: string | undefined): number {
  const t = (triggerType || "").toLowerCase();
  if (t === "high") return 22;
  if (t === "medium") return 14;
  if (t === "low" || t === "info") return 8;
  return 12;
}

/**
 * Fuse forensic signals + RCU trigger results into a single risk score / verdict.
 */
export function fuseForensicVerdict(
  signals: ForensicSignal[],
  triggerResults: TriggerResultItem[]
): ForensicSummary {
  let score = 0;
  const reasons: string[] = [];

  for (const s of signals) {
    if (s.status === "failed") {
      score += s.score;
      reasons.push(`${s.threatCode}: ${s.title}`);
    }
  }

  let failedTriggerCount = 0;
  for (const t of triggerResults) {
    if (t.status === "failed") {
      failedTriggerCount++;
      score += riskWeight(t.triggerType);
      reasons.push(`RCU ${t.field}: ${t.message || "Failed"}`);
    }
  }

  score = Math.max(0, Math.min(100, Math.round(score)));

  const failedSignalCount = signals.filter((s) => s.status === "failed").length;
  const highFails = signals.filter((s) => s.status === "failed" && s.severity === "high");
  const tamperCodes = new Set([
    "VISUAL_TAMPER_DETECTED",
    "IMAGE_ELA_ANOMALY",
    "IMAGE_EDITOR_SIGNATURE",
    "IMAGE_EDITOR_METADATA",
    "PDF_ANNOTATIONS_PRESENT",
    "PDF_INCREMENTAL_UPDATE",
    "DOC_TRACKED_CHANGES",
    "DOC_MODIFIED_AFTER_CREATE",
    "DOC_RTF_MARKUP_EDITS",
    "ZIP_SUSPICIOUS_ENTRIES",
  ]);
  const hasTamperFail = signals.some(
    (s) => s.status === "failed" && tamperCodes.has(String(s.code || "").toUpperCase())
  );

  let verdict: ForensicVerdict;
  // Tamper / edit evidence must never land as Genuine
  if (hasTamperFail && score >= 55) verdict = "TEMP";
  else if (hasTamperFail) verdict = "SUSPICIOUS";
  else if (score >= 70) verdict = "TEMP";
  else if (score >= 40) verdict = "SUSPICIOUS";
  else if (score >= 22) verdict = "LIKELY_GENUINE";
  else if (failedTriggerCount > 0 || failedSignalCount > 0) verdict = "MANUAL_REVIEW";
  else verdict = "GENUINE";

  // Soft edge: any high forensic fail → at least SUSPICIOUS (never Genuine)
  if (
    highFails.length > 0 &&
    (verdict === "GENUINE" || verdict === "LIKELY_GENUINE")
  ) {
    verdict = "SUSPICIOUS";
  }

  // Multiple independent fails escalate
  if (failedSignalCount >= 3 && score >= 35 && verdict !== "TEMP") {
    verdict = "SUSPICIOUS";
  }
  if (failedSignalCount >= 2 && hasTamperFail && score >= 45) {
    verdict = "TEMP";
  }

  const verdictLabel: Record<ForensicVerdict, string> = {
    GENUINE: "Genuine",
    LIKELY_GENUINE: "Likely Genuine",
    SUSPICIOUS: "Suspicious",
    TEMP: "Temp",
    MANUAL_REVIEW: "Manual Review",
  };

  return {
    riskScore: score,
    verdict,
    verdictLabel: verdictLabel[verdict],
    reasons: reasons.slice(0, 12),
    failedSignalCount,
    failedTriggerCount,
  };
}

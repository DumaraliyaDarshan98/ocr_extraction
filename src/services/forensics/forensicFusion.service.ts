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

  let verdict: ForensicVerdict;
  if (score >= 75) verdict = "TEMP";
  else if (score >= 50) verdict = "SUSPICIOUS";
  else if (score >= 25) verdict = "LIKELY_GENUINE";
  else if (failedTriggerCount > 0 || failedSignalCount > 0) verdict = "MANUAL_REVIEW";
  else verdict = "GENUINE";

  // Soft edge: any high forensic fail with mid score → at least SUSPICIOUS
  if (
    signals.some((s) => s.status === "failed" && s.severity === "high") &&
    score >= 20 &&
    (verdict === "GENUINE" || verdict === "LIKELY_GENUINE")
  ) {
    verdict = "SUSPICIOUS";
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

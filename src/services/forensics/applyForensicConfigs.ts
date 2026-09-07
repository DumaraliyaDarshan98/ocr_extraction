import type { ForensicSignal } from "./fileIntegrity.service";
import type { ForensicSummary } from "./forensicFusion.service";
import { fuseForensicVerdict } from "./forensicFusion.service";
import type { TriggerResultItem } from "../../types/kyc.types";
import type { ForensicFileCategory } from "./detectFileCategory";

export type ForensicConfigItem = {
  code: string;
  engineKey?: string;
  threatCode?: string;
  title?: string;
  description?: string;
  severity?: "low" | "medium" | "high";
  score?: number;
  category?: ForensicFileCategory | string;
  documentTypePattern?: string | null;
};

function matchesDocumentType(
  pattern: string,
  documentType: string | undefined
): boolean {
  const dt = (documentType || "").toLowerCase();
  const p = pattern.trim();
  if (!p) return true;
  try {
    return new RegExp(p, "i").test(dt);
  } catch {
    return dt.includes(p.toLowerCase());
  }
}

/** Fail-oriented checks that are mutually exclusive with a “clean” sibling. */
function cleanSiblingKey(engineKey: string): string | null {
  const k = engineKey.toUpperCase();
  if (k === "FILE_FORMAT_MISMATCH" || k === "FILE_SIGNATURE_UNKNOWN") {
    return "FILE_INTEGRITY_OK";
  }
  if (k === "DOC_FORMAT_MISMATCH" || k === "DOC_SIGNATURE_UNKNOWN") {
    return "DOC_INTEGRITY_OK";
  }
  if (k === "ZIP_FORMAT_MISMATCH" || k === "ZIP_SIGNATURE_UNKNOWN" || k === "ZIP_EMPTY_ARCHIVE") {
    return "ZIP_INTEGRITY_OK";
  }
  if (k === "PDF_MODIFIED_AFTER_CREATE") return "PDF_DATE_CONSISTENT";
  if (k === "PDF_PRODUCER_ANOMALY" || k === "PDF_PRODUCER_MISSING") {
    return "PDF_PRODUCER_RECORDED";
  }
  if (k === "SALARY_NET_MISMATCH") return "SALARY_MATH_OK";
  if (k === "BANK_BALANCE_MISMATCH") return "BANK_MATH_OK";
  return null;
}

function isFailOriented(engineKey: string): boolean {
  const k = engineKey.toUpperCase();
  return (
    k.includes("MISMATCH") ||
    k.includes("ANOMALY") ||
    k.includes("UNKNOWN") ||
    k.includes("EMPTY") ||
    k.includes("LAYOUT") ||
    k.includes("GAP") ||
    k.endsWith("_MISSING")
  );
}

/**
 * Merge admin catalog with engine signals (trigger-style):
 * every configured check becomes a report row.
 * - engine emitted → use that outcome (+ admin overlays)
 * - not possible to run → skipped (yellow Skip in UI)
 * - clean / no finding → passed
 */
export function applyForensicConfigs(
  signals: ForensicSignal[],
  configs: ForensicConfigItem[] | null | undefined,
  documentType?: string,
  triggerResults?: TriggerResultItem[]
): { signals: ForensicSignal[]; forensicSummary: ForensicSummary } {
  if (configs == null) {
    const forensicSummary = fuseForensicVerdict(signals, triggerResults ?? []);
    return { signals, forensicSummary };
  }

  const signalsByKey = new Map<string, ForensicSignal>();
  for (const s of signals) {
    const key = String(s.code || "").trim().toUpperCase();
    if (key) signalsByKey.set(key, s);
  }

  const hasInsufficientSalary = [...signalsByKey.keys()].some((k) =>
    k.includes("INSUFFICIENT")
  );

  const next: ForensicSignal[] = [];

  for (const cfg of configs) {
    if (!cfg || typeof cfg !== "object") continue;
    const code = String(cfg.code || "").trim();
    if (!code) continue;
    const engineKey = String(cfg.engineKey || cfg.code || "")
      .trim()
      .toUpperCase();
    if (!engineKey) continue;

    const title = (cfg.title || code).trim();
    const threatCode = String(cfg.threatCode || "").trim() || "T000";
    const severity =
      cfg.severity === "low" || cfg.severity === "medium" || cfg.severity === "high"
        ? cfg.severity
        : "low";
    const configuredScore =
      typeof cfg.score === "number" && Number.isFinite(cfg.score)
        ? Math.max(0, Math.min(100, Math.round(cfg.score)))
        : 0;

    const pattern = (cfg.documentTypePattern || "").trim();
    const eng = signalsByKey.get(engineKey);

    // Engine produced a signal — always surface it.
    if (eng) {
      // Map "info insufficient" to Skip for clearer UI
      if (
        eng.status === "info" &&
        /insufficient|not fully checkable|not checkable/i.test(
          `${eng.code} ${eng.title} ${eng.description}`
        )
      ) {
        next.push({
          ...eng,
          code,
          threatCode: threatCode || eng.threatCode,
          title: title || eng.title,
          severity,
          score: 0,
          status: "skipped",
          description:
            eng.description ||
            `Skip — not enough data to run this check on document type "${documentType || "unknown"}".`,
        });
        continue;
      }

      const failed = eng.status === "failed";
      next.push({
        ...eng,
        code,
        threatCode: threatCode || eng.threatCode,
        title: title || eng.title,
        severity: failed ? severity : eng.severity,
        score: failed ? configuredScore || eng.score : 0,
        description: eng.description || cfg.description || title,
      });
      continue;
    }

    // Content filter: cannot run on this document type
    if (pattern && !matchesDocumentType(pattern, documentType)) {
      next.push({
        code,
        threatCode,
        severity,
        score: 0,
        status: "skipped",
        title,
        description: `Skip — not applicable for document type "${documentType || "unknown"}" (filter: ${pattern}).`,
      });
      continue;
    }

    // Fail-oriented check with a clean sibling already passed → Genuine (no issue)
    const sibling = cleanSiblingKey(engineKey);
    if (sibling && signalsByKey.get(sibling)?.status === "passed") {
      next.push({
        code,
        threatCode,
        severity,
        score: 0,
        status: "passed",
        title,
        description: "No issue detected for this check on the uploaded file.",
      });
      continue;
    }

    // Fail-oriented salary/bank check but insufficient extracted fields → Skip
    if (
      isFailOriented(engineKey) &&
      (hasInsufficientSalary ||
        ((engineKey.includes("SALARY") || engineKey.includes("BANK")) &&
          !signals.some((s) => s.code.toUpperCase().includes("SALARY") || s.code.toUpperCase().includes("BANK"))))
    ) {
      next.push({
        code,
        threatCode,
        severity,
        score: 0,
        status: "skipped",
        title,
        description: `Skip — not possible to run this check on the uploaded document (missing or insufficient fields).`,
      });
      continue;
    }

    // Default: no finding
    next.push({
      code,
      threatCode,
      severity,
      score: 0,
      status: "passed",
      title,
      description:
        (cfg.description || "").trim() ||
        "No issue detected for this check on the uploaded file.",
    });
  }

  // Keep engine failures that are not yet in the admin catalog (new checks).
  const coveredKeys = new Set(
    configs
      .map((c) => String(c?.engineKey || c?.code || "").trim().toUpperCase())
      .filter(Boolean)
  );
  for (const s of signals) {
    const key = String(s.code || "").trim().toUpperCase();
    if (!key || coveredKeys.has(key)) continue;
    if (s.status !== "failed") continue;
    next.push(s);
  }

  const forensicSummary = fuseForensicVerdict(next, triggerResults ?? []);
  return { signals: next, forensicSummary };
}

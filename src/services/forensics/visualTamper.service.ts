import type { ForensicSignal } from "./fileIntegrity.service";

function unwrap(value: unknown): unknown {
  if (value && typeof value === "object" && !Array.isArray(value) && "value" in value) {
    return (value as { value: unknown }).value;
  }
  return value;
}

function asBool(value: unknown): boolean | null {
  const v = unwrap(value);
  if (typeof v === "boolean") return v;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    if (["true", "yes", "1", "y"].includes(s)) return true;
    if (["false", "no", "0", "n", "null", ""].includes(s)) return false;
  }
  if (typeof v === "number") return v !== 0;
  return null;
}

function asStringList(value: unknown): string[] {
  const v = unwrap(value);
  if (v == null) return [];
  if (Array.isArray(v)) {
    return v
      .map((x) => String(unwrap(x) ?? "").trim())
      .filter(Boolean);
  }
  const s = String(v).trim();
  if (!s || s.toLowerCase() === "null") return [];
  if (s.startsWith("[")) {
    try {
      const parsed = JSON.parse(s);
      if (Array.isArray(parsed)) {
        return parsed.map((x) => String(x).trim()).filter(Boolean);
      }
    } catch {
      /* fall through */
    }
  }
  return s.split(/[,|;]/).map((p) => p.trim()).filter(Boolean);
}

/**
 * Convert Gemini / extraction tampering fields into forensic risk signals.
 * These catch marks, whiteouts, erased text that binary checks miss.
 */
export function analyzeVisualTamperFromExtracted(
  extractedData?: Record<string, unknown> | null
): ForensicSignal[] {
  if (!extractedData || typeof extractedData !== "object") return [];

  const keys = Object.keys(extractedData);
  const findKey = (...names: string[]) =>
    keys.find((k) => names.includes(k.toLowerCase().replace(/[^a-z0-9]/g, "")));

  const tamperKey = findKey("tamperingdetected", "tampering_detected", "istampered");
  const typeKey = findKey("tamperingtype", "tampering_type", "tamperingtypes");

  const detected = tamperKey ? asBool(extractedData[tamperKey]) : null;
  const types = typeKey ? asStringList(extractedData[typeKey]) : [];

  const signals: ForensicSignal[] = [];

  if (detected === true || types.length > 0) {
    const typeLabel = types.length ? types.join(", ") : "unspecified visual anomaly";
    signals.push({
      code: "VISUAL_TAMPER_DETECTED",
      threatCode: "T050",
      severity: "high",
      score: 40,
      status: "failed",
      title: "Visual tampering detected",
      description: `Document shows signs of editing or covering (marks / whiteout / text removal / overwrite): ${typeLabel}.`,
      evidence: { tamperingDetected: true, tamperingType: types },
    });
  } else if (detected === false) {
    signals.push({
      code: "VISUAL_TAMPER_CLEAR",
      threatCode: "T050",
      severity: "low",
      score: 0,
      status: "passed",
      title: "No visual tampering flagged",
      description: "Extraction model did not report visible marks, whiteouts, or text manipulation.",
    });
  } else {
    signals.push({
      code: "VISUAL_TAMPER_UNAVAILABLE",
      threatCode: "T050",
      severity: "low",
      score: 0,
      status: "info",
      title: "Visual tamper fields missing",
      description: "Extraction did not return tamperingDetected — re-run OCR after prompt update.",
    });
  }

  return signals;
}

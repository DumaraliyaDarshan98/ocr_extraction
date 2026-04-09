/**
 * Converts Gemini nested shape { field: { value, confidence } } into flat data + confidence map.
 * Legacy flat primitives pass through with no confidence entry.
 */
export function normalizeExtractedPayload(raw: Record<string, unknown>): {
  flat: Record<string, unknown>;
  confidence: Record<string, number>;
} {
  const flat: Record<string, unknown> = {};
  const confidence: Record<string, number> = {};

  for (const [key, v] of Object.entries(raw)) {
    if (
      v !== null &&
      typeof v === "object" &&
      !Array.isArray(v) &&
      "value" in (v as object)
    ) {
      const o = v as { value?: unknown; confidence?: unknown };
      flat[key] = o.value ?? null;
      if (typeof o.confidence === "number" && Number.isFinite(o.confidence)) {
        confidence[key] = Math.max(0, Math.min(1, o.confidence));
      }
    } else {
      flat[key] = v;
    }
  }

  return { flat, confidence };
}

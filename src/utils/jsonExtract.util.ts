/**
 * Extracts a JSON value from model output that may include markdown fences or prose.
 */

function extractBalancedObject(text: string, startIdx: number): string | null {
  if (text[startIdx] !== "{") {
    return null;
  }
  let depth = 0;
  let inString = false;
  let escape = false;

  for (let i = startIdx; i < text.length; i++) {
    const ch = text[i];

    if (inString) {
      if (escape) {
        escape = false;
        continue;
      }
      if (ch === "\\") {
        escape = true;
        continue;
      }
      if (ch === '"') {
        inString = false;
      }
      continue;
    }

    if (ch === '"') {
      inString = true;
      continue;
    }

    if (ch === "{") {
      depth += 1;
    } else if (ch === "}") {
      depth -= 1;
      if (depth === 0) {
        return text.slice(startIdx, i + 1);
      }
    }
  }

  return null;
}

/**
 * Parses JSON from LLM text: tries full parse, fenced blocks, then first balanced `{...}`.
 */
export function parseJsonFromModelText(text: string): unknown {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new Error("Empty model response");
  }

  const fence =
    /^```(?:json)?\s*\r?\n?([\s\S]*?)\r?\n?```/im.exec(trimmed);
  const inner = fence?.[1];
  const candidate =
    inner !== undefined && inner !== "" ? inner.trim() : trimmed;

  try {
    return JSON.parse(candidate);
  } catch {
    // continue
  }

  const start = candidate.indexOf("{");
  if (start === -1) {
    throw new Error("No JSON object found in model response");
  }

  const balanced = extractBalancedObject(candidate, start);
  if (!balanced) {
    throw new Error("Unbalanced JSON object in model response");
  }

  return JSON.parse(balanced) as unknown;
}

/**
 * Ensures the parsed value is a non-null object suitable for field validation.
 */
export function parseJsonObjectFromModelText(text: string): Record<string, unknown> {
  const parsed = parseJsonFromModelText(text);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Model JSON must be a plain object");
  }
  return parsed as Record<string, unknown>;
}

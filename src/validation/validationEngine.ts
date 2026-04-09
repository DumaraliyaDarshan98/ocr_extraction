import type {
  CustomValidatorRegistry,
  FieldValidationError,
  TriggerConfigFile,
  TriggerRuleResult,
  TriggerRule,
  ValidationEngineResult,
} from "./types";

function normalizeDocType(s: string): string {
  return s.trim().toLowerCase();
}

function getFieldValue(
  data: Record<string, unknown>,
  field: string
): unknown {
  if (Object.prototype.hasOwnProperty.call(data, field)) {
    return data[field];
  }
  const target = field.toLowerCase();
  const key = Object.keys(data).find((k) => k.toLowerCase() === target);
  return key !== undefined ? data[key] : undefined;
}

function asTrimmedString(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }
  return String(value).trim();
}

function parseNumberCondition(raw: string | undefined, label: string): number {
  if (raw === undefined || raw === "") {
    throw new Error(`${label} requires a numeric condition`);
  }
  const n = Number(raw);
  if (Number.isNaN(n)) {
    throw new Error(`${label} condition must be a number, got: ${raw}`);
  }
  return n;
}

function parseOneOfList(condition: string | undefined): string[] {
  if (!condition || !condition.trim()) {
    return [];
  }
  const t = condition.trim();
  if (t.startsWith("[") && t.endsWith("]")) {
    try {
      const parsed = JSON.parse(t) as unknown;
      if (Array.isArray(parsed)) {
        return parsed.map((x) => String(x).trim());
      }
    } catch {
      /* fall through */
    }
  }
  return t.split(",").map((s) => s.trim()).filter(Boolean);
}

function evaluateRule(
  rule: TriggerRule,
  data: Record<string, unknown>,
  customValidators: CustomValidatorRegistry | undefined
): boolean {
  const value = getFieldValue(data, rule.field);
  const str = asTrimmedString(value);

  switch (rule.triggerType) {
    case "required": {
      if (value === null || value === undefined) {
        return false;
      }
      if (typeof value === "string") {
        return value.trim().length > 0;
      }
      if (typeof value === "number" || typeof value === "boolean") {
        return true;
      }
      return str.length > 0;
    }
    case "regex": {
      if (!rule.condition || rule.condition === "") {
        throw new Error(`regex rule for field "${rule.field}" needs condition (pattern)`);
      }
      const re = new RegExp(rule.condition);
      return re.test(str);
    }
    case "minLength": {
      const min = parseNumberCondition(rule.condition, "minLength");
      return str.length >= min;
    }
    case "maxLength": {
      const max = parseNumberCondition(rule.condition, "maxLength");
      return str.length <= max;
    }
    case "match": {
      const otherField = rule.secondaryField ?? rule.condition;
      if (!otherField || otherField === "") {
        throw new Error(
          `match rule for field "${rule.field}" needs secondaryField or condition (other field name)`
        );
      }
      const other = asTrimmedString(getFieldValue(data, otherField));
      return str === other;
    }
    case "contains": {
      if (rule.condition === undefined) {
        throw new Error(`contains rule for field "${rule.field}" needs condition`);
      }
      return str.includes(rule.condition);
    }
    case "notContains": {
      if (rule.condition === undefined) {
        throw new Error(`notContains rule for field "${rule.field}" needs condition`);
      }
      return !str.includes(rule.condition);
    }
    case "equals": {
      if (rule.condition === undefined) {
        throw new Error(`equals rule for field "${rule.field}" needs condition`);
      }
      return str === rule.condition;
    }
    case "oneOf": {
      const options = parseOneOfList(rule.condition);
      if (options.length === 0) {
        throw new Error(`oneOf rule for field "${rule.field}" needs condition (CSV or JSON array)`);
      }
      return options.some((o) => o === str);
    }
    case "custom": {
      const key = rule.customKey ?? rule.condition;
      if (!key || !customValidators || !customValidators[key]) {
        throw new Error(
          `custom rule for field "${rule.field}" needs customKey/condition and a registered validator "${key}"`
        );
      }
      return customValidators[key](value, data, rule);
    }
    default: {
      const _exhaustive: never = rule.triggerType;
      throw new Error(`Unsupported trigger type: ${String(_exhaustive)}`);
    }
  }
}

/**
 * Runs all triggers for the given document type against flat extracted data.
 * No document-specific logic is hardcoded; rules come entirely from JSON.
 */
export function runValidationEngine(
  documentType: string,
  extractedData: Record<string, unknown>,
  config: TriggerConfigFile,
  customValidators?: CustomValidatorRegistry
): ValidationEngineResult {
  const dt = normalizeDocType(documentType);
  const rules = config.triggers
    .filter((r) => normalizeDocType(r.documentType) === dt)
    .sort((a, b) => (a.order ?? 0) - (b.order ?? 0));

  const errors: FieldValidationError[] = [];
  const ruleResults: TriggerRuleResult[] = [];

  for (const rule of rules) {
    try {
      const ok = evaluateRule(rule, extractedData, customValidators);
      ruleResults.push({
        field: rule.field,
        triggerType: rule.triggerType,
        passed: ok,
        message: ok ? "Passed" : rule.errorMessage,
      });
      if (!ok) {
        errors.push({ field: rule.field, message: rule.errorMessage });
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      ruleResults.push({
        field: rule.field,
        triggerType: rule.triggerType,
        passed: false,
        message: msg,
      });
      errors.push({ field: rule.field, message: msg });
    }
  }

  return {
    documentType: documentType.trim(),
    valid: errors.length === 0,
    errors,
    ruleResults,
  };
}

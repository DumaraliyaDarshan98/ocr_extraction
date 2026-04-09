/**
 * Trigger types supported by the config-driven validation engine.
 * Add new kinds here and implement them in validationEngine.ts.
 */
export type TriggerType =
  | "required"
  | "regex"
  | "minLength"
  | "maxLength"
  | "match"
  | "contains"
  | "notContains"
  | "equals"
  | "oneOf"
  | "custom";

/**
 * One row from Excel / one entry in JSON.
 * - `condition` meaning depends on `triggerType` (pattern, literal, other field name, CSV list, etc.).
 * - `secondaryField` can hold the other field for cross-field rules when you prefer not to put it in `condition`.
 */
export interface TriggerRule {
  documentType: string;
  field: string;
  triggerType: TriggerType;
  errorMessage: string;
  condition?: string;
  secondaryField?: string;
  /** Lower runs first; default 0 */
  order?: number;
  /** For triggerType "custom": key looked up in CustomValidatorRegistry */
  customKey?: string;
}

export interface TriggerConfigFile {
  version: number;
  triggers: TriggerRule[];
}

export interface FieldValidationError {
  field: string;
  message: string;
}

export interface ValidationEngineResult {
  documentType: string;
  valid: boolean;
  errors: FieldValidationError[];
  ruleResults: TriggerRuleResult[];
}

export interface TriggerRuleResult {
  field: string;
  triggerType: TriggerType;
  passed: boolean;
  message: string;
}

export type CustomValidatorFn = (
  value: unknown,
  data: Record<string, unknown>,
  rule: TriggerRule
) => boolean;

export type CustomValidatorRegistry = Record<string, CustomValidatorFn>;

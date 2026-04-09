import * as XLSX from "xlsx";
import type { TriggerConfigFile, TriggerRule, TriggerType } from "../validation/types";

const HEADER_ALIASES: Record<string, keyof TriggerRule | "skip"> = {
  "document type": "documentType",
  documenttype: "documentType",
  document_type: "documentType",
  document: "documentType",
  field: "field",
  "field పేరు": "field",
  "field name": "field",
  fieldname: "field",
  "trigger type": "triggerType",
  triggertype: "triggerType",
  trigger_type: "triggerType",
  condition: "condition",
  "error message": "errorMessage",
  errormessage: "errorMessage",
  error_message: "errorMessage",
  message: "errorMessage",
  "secondary field": "secondaryField",
  secondaryfield: "secondaryField",
  secondary_field: "secondaryField",
  order: "order",
  "custom key": "customKey",
  customkey: "customKey",
};

function normalizeHeader(h: string): string {
  return h.replace(/\uFEFF/g, "").trim().toLowerCase();
}

function mapHeader(cell: string): keyof TriggerRule | null {
  const key = normalizeHeader(cell);
  const mapped = HEADER_ALIASES[key];
  if (mapped === "skip") {
    return null;
  }
  if (mapped) {
    return mapped as keyof TriggerRule;
  }
  return null;
}

function coerceTriggerType(raw: unknown): TriggerType {
  const s = String(raw ?? "").trim().toLowerCase();
  const allowed: TriggerType[] = [
    "required",
    "regex",
    "minLength",
    "maxLength",
    "match",
    "contains",
    "notContains",
    "equals",
    "oneOf",
    "custom",
  ];
  const found = allowed.find((x) => x.toLowerCase() === s);
  if (!found) {
    throw new Error(`Unknown trigger type: ${String(raw)}`);
  }
  return found;
}

function rowToRule(row: Record<string, unknown>): TriggerRule {
  const cells: Partial<Record<keyof TriggerRule, unknown>> = {};
  for (const [k, v] of Object.entries(row)) {
    const mapped = mapHeader(k);
    if (mapped) {
      cells[mapped] = v;
    }
  }

  const documentType = String(cells.documentType ?? "").trim();
  const field = String(cells.field ?? "").trim();
  const triggerType = coerceTriggerType(cells.triggerType);
  const errorMessage = String(cells.errorMessage ?? "").trim();

  if (!documentType || !field || !errorMessage) {
    throw new Error(
      `Row missing documentType, field, or errorMessage (got documentType=${documentType}, field=${field})`
    );
  }

  const rule: TriggerRule = {
    documentType,
    field,
    triggerType,
    errorMessage,
  };

  if (cells.condition !== undefined && cells.condition !== "") {
    rule.condition = String(cells.condition);
  }
  if (cells.secondaryField !== undefined && cells.secondaryField !== "") {
    rule.secondaryField = String(cells.secondaryField);
  }
  if (cells.order !== undefined && cells.order !== "") {
    rule.order = Number(cells.order);
  }
  if (cells.customKey !== undefined && cells.customKey !== "") {
    rule.customKey = String(cells.customKey);
  }

  return rule;
}

/**
 * Converts first worksheet of an .xlsx to a TriggerConfigFile.
 * Expects a header row with columns like Document Type, Field, Trigger Type, Condition, Error Message.
 */
export function excelBufferToTriggerConfig(
  buffer: Buffer,
  version = 1
): TriggerConfigFile {
  const wb = XLSX.read(buffer, { type: "buffer" });
  const sheetName = wb.SheetNames[0];
  if (!sheetName) {
    throw new Error("Workbook has no sheets");
  }
  const sheet = wb.Sheets[sheetName];
  if (!sheet) {
    throw new Error(`Sheet "${sheetName}" could not be read`);
  }
  const rows = XLSX.utils.sheet_to_json<Record<string, unknown>>(sheet, {
    defval: "",
    raw: false,
  });

  const triggers: TriggerRule[] = [];
  for (const row of rows) {
    const hasAny = Object.values(row).some(
      (v) => String(v ?? "").trim() !== ""
    );
    if (!hasAny) {
      continue;
    }
    triggers.push(rowToRule(row));
  }

  return { version, triggers };
}

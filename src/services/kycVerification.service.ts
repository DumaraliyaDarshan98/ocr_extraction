import { extractText } from "./ocr.service";
import { detectKeywords } from "../utils/keyword.util";
import { extractStructuredDataFromDocument } from "./geminiExtraction.service";
import { loadTriggerConfig, hasTriggersForDocumentType } from "./triggerConfig.service";
import { runValidationEngine } from "../validation/validationEngine";
import { analyzeDocumentAI } from "./aiVerification.service";
import { validateAadhaar } from "../validators/aadhaar.validator";
import { validatePAN } from "../validators/pan.validator";
import { validatePassport } from "../validators/passport.validator";
import { validateDrivingLicense } from "../validators/drivingLicense.validator";
import { computeNameMatchScorePercent } from "./nameMatch.service";
import { validateDobIso } from "./dobValidation.service";
import { compareFaceImages } from "./faceMatch.service";
import { getKycThresholds } from "../config/kyc.config";
import type {
  KycApiResponse,
  KycCheck,
  KycError,
  TriggerResultItem,
} from "../types/kyc.types";
import type { TriggerConfigFile, TriggerRule } from "../validation/types";
import type { CustomValidatorRegistry } from "../validation/types";

export interface KycRunOptions {
  documentType: string;
  documentPath: string;
  documentMimeType?: string | undefined;
  selfiePath?: string | undefined;
  expectedName?: string | undefined;
  /** If true, missing DOB in extraction counts as failure */
  requireDob?: boolean | undefined;
}

function pickFirstString(
  data: Record<string, unknown>,
  keys: string[]
): string | undefined {
  for (const k of keys) {
    const lower = k.toLowerCase();
    const found = Object.keys(data).find((dk) => dk.toLowerCase() === lower);
    if (found) {
      const v = data[found];
      if (v !== null && v !== undefined && String(v).trim() !== "") {
        return String(v).trim();
      }
    }
  }
  return undefined;
}

function legacyNumberValid(
  normalizedType: string,
  ocrText: string
): { ok: boolean; message?: string } {
  switch (normalizedType) {
    case "aadhaar": {
      const r = validateAadhaar(ocrText);
      return r.valid ? { ok: true } : { ok: false, message: "Aadhaar validation failed" };
    }
    case "pan": {
      const r = validatePAN(ocrText);
      return r.valid ? { ok: true } : { ok: false, message: "PAN validation failed" };
    }
    case "passport": {
      const r = validatePassport(ocrText);
      return r.valid ? { ok: true } : { ok: false, message: "Passport validation failed" };
    }
    case "driving license":
    case "driving_license": {
      const r = validateDrivingLicense(ocrText);
      return r.valid ? { ok: true } : { ok: false, message: "Driving license validation failed" };
    }
    default:
      return { ok: false, message: "Document type not supported" };
  }
}

function buildMessage(errors: KycError[], isValid: boolean): string {
  if (isValid) {
    return "Verification passed";
  }
  return errors.map((e) => e.message).join("; ");
}

function normKey(k: string): string {
  return k.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function getRulesForType(
  documentType: string,
  config: TriggerConfigFile
): TriggerRule[] {
  const dt = documentType.trim().toLowerCase();
  return config.triggers.filter(
    (r) => r.documentType.trim().toLowerCase() === dt
  );
}

function parseDobToIso(input: string): string | null {
  const s = input.trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) {
    return s;
  }
  const m = /^(\d{2})[\/\-](\d{2})[\/\-](\d{4})$/.exec(s);
  if (!m) {
    return null;
  }
  const dd = m[1];
  const mm = m[2];
  const yyyy = m[3];
  return `${yyyy}-${mm}-${dd}`;
}

function normalizeExtractedForValidation(
  extracted: Record<string, unknown>,
  documentType: string,
  config: TriggerConfigFile,
  dobFieldKeys: string[]
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...extracted };
  const rules = getRulesForType(documentType, config);

  const entries = Object.entries(extracted);
  const explicitAliases: Record<string, string[]> = {
    aadhaar: ["aadhaarnumber", "aadharnumber", "uid", "uidnumber"],
    voterid: ["epic", "epicno", "epicnumber", "voterno", "voteridnumber"],
    drivinglicensenumber: ["dlnumber", "dlno", "licenseno", "licenceno"],
    dob: ["dateofbirth", "birthdate"],
    bankaccountnumber: ["accountnumber", "accountno", "accnumber", "accno"],
    bankname: ["bank"],
    statementissuedate: ["issuedate", "dateofissue"],
    chequenumbers: ["chequenumber", "chequeno", "chequeseries", "chequenumbers"],
    employername: ["employer", "companyname", "company"],
    grosssalary: ["gross", "grosssalary"],
    netsalary: ["net", "netsalary", "takehome"],
    salarymonth: ["month", "salarymonth"],
    designation: ["designation", "designationtitle", "role"],
    monthlyincome: ["monthlyincome", "income", "salary"],
  };

  // 1) Alias mapping by normalized key containment (e.g. aadhaarNumber -> aadhaar)
  for (const rule of rules) {
    const target = rule.field;
    const already = Object.keys(out).find(
      (k) => k.toLowerCase() === target.toLowerCase()
    );
    if (already) {
      continue;
    }
    const targetNorm = normKey(target);
    const candidate = entries.find(([k, v]) => {
      if (v === null || v === undefined || String(v).trim() === "") {
        return false;
      }
      const kn = normKey(k);
      const aliases = explicitAliases[targetNorm] ?? [];
      if (aliases.includes(kn)) {
        return true;
      }
      return kn.includes(targetNorm) || targetNorm.includes(kn);
    });
    if (candidate) {
      out[target] = candidate[1];
    }
  }

  // 2) Numeric regex cleanup (remove spaces/hyphens/etc before regex check)
  for (const rule of rules) {
    if (rule.triggerType !== "regex" || !rule.condition) {
      continue;
    }

    // Only attempt numeric cleanup for regexes that look like digits-only.
    // If the condition contains any uppercase letters, we skip (e.g., PAN/GSTIN).
    const condition = rule.condition;
    const hasDigitTokens = condition.includes("\\d") || condition.includes("[0-9]");
    const hasUppercaseAlpha = /[A-Z]/.test(condition);
    if (!hasDigitTokens || hasUppercaseAlpha) {
      continue;
    }

    const key = Object.keys(out).find(
      (k) => k.toLowerCase() === rule.field.toLowerCase()
    );
    if (!key) {
      continue;
    }
    const raw = out[key];
    if (typeof raw === "string") {
      out[key] = raw.replace(/\D/g, "");
    }
  }

  // 3) DOB normalization to YYYY-MM-DD (for both trigger engine and age check)
  for (const dobKey of dobFieldKeys) {
    const key = Object.keys(out).find(
      (k) => k.toLowerCase() === dobKey.toLowerCase()
    );
    if (!key) {
      continue;
    }
    const v = out[key];
    if (typeof v !== "string") {
      continue;
    }
    const iso = parseDobToIso(v);
    if (iso) {
      out[key] = iso;
    }
  }

  // 4) Generic ISO date normalization for any trigger that expects ISO dates.
  // (Helps when Gemini outputs DD/MM/YYYY for non-DOB date fields like statement dates.)
  for (const rule of rules) {
    if (rule.triggerType !== "regex" || !rule.condition) {
      continue;
    }
    const expectsIsoDate = rule.condition.includes("\\d{4}-\\d{2}-\\d{2}");
    if (!expectsIsoDate) {
      continue;
    }
    const key = Object.keys(out).find(
      (k) => k.toLowerCase() === rule.field.toLowerCase()
    );
    if (!key) {
      continue;
    }
    const v = out[key];
    if (typeof v !== "string") {
      continue;
    }
    const iso = parseDobToIso(v);
    if (iso) {
      out[key] = iso;
    }
  }

  return out;
}

function buildCustomValidators(): CustomValidatorRegistry {
  return {
    panFourthCharAllowed: (value, _data, rule) => {
      const pan = String(value ?? "").trim().toUpperCase();
      if (pan.length < 4) {
        return false;
      }
      const allowed = (rule.condition ?? "C,P,H,F,A,T,B,L,J,G")
        .split(",")
        .map((x) => x.trim().toUpperCase())
        .filter(Boolean);
      const fourth = pan.charAt(3);
      return allowed.includes(fourth);
    },
    panFifthCharMatchesNameInitial: (value, data, rule) => {
      const pan = String(value ?? "").trim().toUpperCase();
      if (pan.length < 5) {
        return false;
      }
      const nameField = (rule.secondaryField ?? "name").toLowerCase();
      const key = Object.keys(data).find((k) => k.toLowerCase() === nameField);
      const name = String(key ? data[key] : "").trim().toUpperCase();
      const firstAlpha = (name.match(/[A-Z]/) ?? [])[0];
      if (!firstAlpha) {
        return false;
      }
      const fifth = pan.charAt(4);
      return fifth === firstAlpha;
    },
    gstPanMatchesPan: (value, data, rule) => {
      const gstin = String(value ?? "").trim().toUpperCase();
      if (gstin.length < 15) {
        return false;
      }
      // GSTIN = 15 chars:
      // 1-2: State code, 3-12: PAN (10 chars), 13: Entity type code, 14: 'Z', 15: check digit
      const panFromGstin = gstin.substring(2, 12);
      const panKey = (rule.secondaryField ?? "pan").toLowerCase();
      const key = Object.keys(data).find((k) => k.toLowerCase() === panKey);
      const pan = String(key ? data[key] : "").trim().toUpperCase();
      if (!pan) {
        return false;
      }
      return panFromGstin === pan;
    },
    tanFourthCharMatchesDeductorNameInitial: (value, data, rule) => {
      const tan = String(value ?? "").trim().toUpperCase();
      // TAN format: 4 letters + 5 digits + 1 letter
      if (!/^[A-Z]{4}[0-9]{5}[A-Z]$/.test(tan)) {
        return false;
      }
      const fourthChar = tan.charAt(3);

      const deductorField = (rule.secondaryField ?? "deductorName").toLowerCase();
      const key = Object.keys(data).find(
        (k) => k.toLowerCase() === deductorField
      );
      const deductorName = String(key ? data[key] : "").trim().toUpperCase();
      const initial = (deductorName.match(/[A-Z]/) ?? [])[0];
      if (!initial) return false;
      return fourthChar === initial;
    },
    mustBeTrue: (value) => {
      const s = String(value ?? "").trim().toLowerCase();
      if (!s) return false;
      return s === "true" || s === "yes" || s === "1";
    },
    mustBeFalse: (value) => {
      const s = String(value ?? "").trim().toLowerCase();
      if (!s) return false;
      return s === "false" || s === "no" || s === "0";
    },
    formatQualityNotDoubtful: (value) => {
      const s = String(value ?? "").trim().toLowerCase();
      if (!s) return false;
      if (s.includes("doubt") || s.includes("spelling") || s.includes("manipul")) {
        return false;
      }
      return true;
    },
    numericAmountsEqual: (value, data, rule) => {
      const aRaw = String(value ?? "").replace(/[^0-9.]/g, "");
      const a = aRaw ? Number(aRaw) : NaN;
      const otherField = rule.secondaryField ?? rule.condition ?? "";
      if (!otherField) return false;
      const k = Object.keys(data).find(
        (dk) => dk.toLowerCase() === String(otherField).toLowerCase()
      );
      const bVal = k ? data[k] : undefined;
      const bRaw = String(bVal ?? "").replace(/[^0-9.]/g, "");
      const b = bRaw ? Number(bRaw) : NaN;
      if (!Number.isFinite(a) || !Number.isFinite(b)) return false;
      return Math.abs(a - b) < 0.01;
    },
    workingDaysMatchesMonthDays: (value, data, rule) => {
      const aRaw = String(value ?? "").replace(/[^0-9]/g, "");
      const bField = rule.secondaryField ?? rule.condition ?? "";
      if (!bField) return false;
      const k = Object.keys(data).find(
        (dk) => dk.toLowerCase() === String(bField).toLowerCase()
      );
      const bVal = k ? data[k] : undefined;
      const bRaw = String(bVal ?? "").replace(/[^0-9]/g, "");
      const aa = aRaw ? Number(aRaw) : NaN;
      const bb = bRaw ? Number(bRaw) : NaN;
      if (!Number.isFinite(aa) || !Number.isFinite(bb)) return false;
      return aa === bb;
    },
    emailDomainNotGeneric: (value) => {
      const s = String(value ?? "").trim().toLowerCase();
      if (!s) return false;
      const domain = s.includes("@") ? s.split("@")[1] ?? "" : s;
      const d = domain ? domain.trim().toLowerCase() : "";
      if (!d || !d.includes(".")) return false;
      const generic = new Set([
        "gmail.com",
        "yahoo.com",
        "outlook.com",
        "hotmail.com",
        "rediffmail.com",
        "live.com",
        "ymail.com",
        "icloud.com",
        "aol.com",
        "proton.me",
        "protonmail.com",
      ]);
      return !generic.has(d);
    },
    pfDeductionRateAtLeast12Percent: (value) => {
      const s = String(value ?? "").replace(/[^0-9.]/g, "");
      const n = s ? Number(s) : NaN;
      if (!Number.isFinite(n)) return false;
      return n >= 12;
    },
    salaryMonthYearNotOlderThanMonths: (value, data, rule) => {
      const otherField = rule.secondaryField ?? "";
      const raw =
        String(value ?? "").trim() ||
        (otherField
          ? (() => {
              const k = Object.keys(data).find(
                (dk) => dk.toLowerCase() === String(otherField).toLowerCase()
              );
              return k ? String(data[k] ?? "").trim() : "";
            })()
          : "");

      const s = raw.trim();
      if (!s) return false;

      let year: number | null = null;
      let month: number | null = null;
      const iso = /^(\\d{4})[-/](\\d{1,2})$/.exec(s);
      if (iso) {
        year = Number(iso[1]);
        month = Number(iso[2]);
      } else {
        const alt = /^(\\d{1,2})[-/](\\d{4})$/.exec(s);
        if (alt) {
          month = Number(alt[1]);
          year = Number(alt[2]);
        }
      }
      if (!year || !month || month < 1 || month > 12) return false;

      const monthsBack = Number(rule.condition ?? "6");
      if (!Number.isFinite(monthsBack)) return false;

      const docDate = new Date(Date.UTC(year, month - 1, 1));
      const now = new Date();
      const nowUtc = new Date(
        Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)
      );
      const diffMonths =
        (nowUtc.getUTCFullYear() - docDate.getUTCFullYear()) * 12 +
        (nowUtc.getUTCMonth() - docDate.getUTCMonth());
      return diffMonths <= monthsBack;
    },
    cashAllowancesBelowThreshold: (value, _data, rule) => {
      const thresholdRaw = String(rule.condition ?? "0").replace(/[^0-9.]/g, "");
      const threshold = thresholdRaw ? Number(thresholdRaw) : 0;
      const vRaw = String(value ?? "").replace(/[^0-9.]/g, "");
      const v = vRaw ? Number(vRaw) : NaN;
      if (!Number.isFinite(v) || !Number.isFinite(threshold)) return false;
      return v <= threshold;
    },
    incomeTaxDeductionRateAtLeast: (value, data, rule) => {
      const taxRaw = String(value ?? "").replace(/[^0-9.]/g, "");
      const tax = taxRaw ? Number(taxRaw) : NaN;
      const grossField = String(rule.secondaryField ?? "");
      if (!grossField) return false;
      const k = Object.keys(data).find(
        (dk) => dk.toLowerCase() === grossField.toLowerCase()
      );
      const grossVal = k ? data[k] : undefined;
      const grossRaw = String(grossVal ?? "").replace(/[^0-9.]/g, "");
      const gross = grossRaw ? Number(grossRaw) : NaN;
      const minRatePctRaw = String(rule.condition ?? "40").replace(/[^0-9.]/g, "");
      const minRatePct = minRatePctRaw ? Number(minRatePctRaw) : 40;
      if (!Number.isFinite(tax) || !Number.isFinite(gross) || gross <= 0) {
        return false;
      }
      const ratePct = (tax / gross) * 100;
      return Number.isFinite(ratePct) && ratePct >= minRatePct;
    },
    signatoryFromFinance: (value) => {
      const s = String(value ?? "").trim().toLowerCase();
      if (!s) return false;
      return s.includes("finance") || s.includes("accounts");
    },
    authenticityScoreAtLeast: (value, _data, rule) => {
      const score = Number(value);
      if (!Number.isFinite(score)) return false;
      const minRaw = rule.condition ?? "";
      const min = Number(minRaw);
      if (!Number.isFinite(min)) return false;
      return score >= min;
    },
    dateNotWeekend: (value) => {
      const iso = String(value ?? "").trim();
      if (!/^\\d{4}-\\d{2}-\\d{2}$/.test(iso)) {
        return false;
      }
      const d = new Date(`${iso}T00:00:00.000Z`);
      if (Number.isNaN(d.getTime())) {
        return false;
      }
      const day = d.getUTCDay(); // 0=Sun, 6=Sat
      return day !== 0 && day !== 6;
    },
    chequeNumbersInSeries: (value, _data, rule) => {
      const s = String(value ?? "");
      const nums = s.match(/\\d+/g)?.map((x) => Number(x)) ?? [];
      if (nums.length < 2) {
        return false;
      }

      const stepMatch = /step=(\\d+)/i.exec(rule.condition ?? "");
      const step = stepMatch ? Number(stepMatch[1]) : 1;
      if (!Number.isFinite(step) || step === 0) {
        return false;
      }

      // Verify consecutive series with the configured step.
      for (let i = 1; i < nums.length; i++) {
        const cur = nums[i];
        const prev = nums[i - 1];
        if (cur === undefined || prev === undefined) {
          return false;
        }
        if (!Number.isFinite(cur) || !Number.isFinite(prev)) {
          return false;
        }
        if (cur - prev !== step) {
          return false;
        }
      }
      return true;
    },
    netSalaryNotExceedGross: (value, data, rule) => {
      const netStr = String(value ?? "").replace(/\\D/g, "");
      const net = netStr ? Number(netStr) : NaN;
      if (!Number.isFinite(net)) {
        return false;
      }

      const grossFieldKey = (rule.secondaryField ?? "grossSalary").toLowerCase();
      const key = Object.keys(data).find((k) => k.toLowerCase() === grossFieldKey);
      const grossStr = key ? String(data[key] ?? "").replace(/\\D/g, "") : "";
      const gross = grossStr ? Number(grossStr) : NaN;
      if (!Number.isFinite(gross)) {
        return false;
      }

      return net <= gross;
    },
  };
}

/**
 * End-to-end KYC: Gemini extraction with per-field confidence, trigger rules, name/DOB/face checks.
 */
export async function runKycVerification(
  options: KycRunOptions
): Promise<KycApiResponse> {
  const thresholds = getKycThresholds();
  const errors: KycError[] = [];
  const checks: KycCheck[] = [];
  const normalizedType = (options.documentType || "").toLowerCase();

  let ocrText = await extractText(options.documentPath, options.documentMimeType);

  let triggerConfig;
  try {
    triggerConfig = loadTriggerConfig();
  } catch {
    triggerConfig = { version: 1, triggers: [] };
  }

  const triggersForType = hasTriggersForDocumentType(
    normalizedType,
    triggerConfig
  );

  let extractedData: Record<string, unknown> = {};
  let confidence: Record<string, number> = {};
  let extractionOk = false;
  let triggerResults: TriggerResultItem[] = [];

  const canUseGemini = !!process.env.GEMINI_API_KEY;

  if (canUseGemini) {
    const extracted = await extractStructuredDataFromDocument(
      options.documentPath,
      normalizedType,
      options.documentMimeType
    );
    if (!extracted) {
      errors.push({
        field: "extraction",
        message: "Gemini extraction unavailable (check GEMINI_API_KEY)",
      });
    } else {
      extractionOk = true;
      extractedData = normalizeExtractedForValidation(
        extracted.data,
        normalizedType,
        triggerConfig,
        thresholds.dobFieldKeys
      );
      confidence = extracted.fieldConfidence;
      // For the generic "Other" flow, we rely on AI forensics flags.
      if (normalizedType === "other") {
        const ai = await analyzeDocumentAI(
          options.documentPath,
          options.documentMimeType
        );
        if (ai) {
          extractedData.possibleTampering = ai.possibleTampering;
          extractedData.layoutConsistent = ai.layoutConsistent;
          extractedData.authenticityScore = ai.authenticityScore;
        }
      }
    }
  }
  checks.push({
    id: "extraction",
    label: "Data extraction",
    source: "document",
    status: extractionOk ? "passed" : "failed",
    details: extractionOk ? "Gemini extracted fields successfully" : "Extraction failed",
  });

  if (triggersForType) {
    if (!canUseGemini) {
      errors.push({
        field: "triggers",
        message: "Trigger validation requires GEMINI_API_KEY for extraction",
      });
    } else if (extractionOk) {
      const fv = runValidationEngine(
        normalizedType,
        extractedData,
        triggerConfig,
        buildCustomValidators()
      );
      triggerResults = fv.ruleResults.map((r) => ({
        field: r.field,
        triggerType: r.triggerType,
        status: r.passed ? "passed" : "failed",
        message: r.message,
      }));
      checks.push({
        id: "trigger-validation",
        label: "Trigger validation",
        source: "document",
        status: fv.valid ? "passed" : "failed",
        details: fv.valid ? "All trigger checks passed" : `${fv.errors.length} trigger check(s) failed`,
      });
      if (!fv.valid) {
        for (const e of fv.errors) {
          errors.push({ field: e.field, message: e.message });
        }
      }
    } else {
      checks.push({
        id: "trigger-validation",
        label: "Trigger validation",
        source: "document",
        status: "failed",
        details: "Skipped because extraction failed",
      });
    }
  } else {
    if (!ocrText && Object.keys(extractedData).length > 0) {
      ocrText = Object.values(extractedData)
        .map((v) => String(v ?? ""))
        .join(" ")
        .toLowerCase();
    }
    const legacy = legacyNumberValid(normalizedType, ocrText);
    checks.push({
      id: "legacy-number-validation",
      label: "Legacy document number validation",
      source: "document",
      status: legacy.ok ? "passed" : "failed",
      details: legacy.ok
        ? "Document number is valid"
        : (legacy.message ?? "Document number validation failed"),
    });
    if (!legacy.ok && legacy.message) {
      errors.push({ field: "document", message: legacy.message });
    }
  }

  let confidenceOk = true;
  const rulesForType = triggersForType
    ? getRulesForType(normalizedType, triggerConfig)
    : [];
  const ruleFieldNorms = new Set(rulesForType.map((r) => normKey(r.field)));

  for (const [key, conf] of Object.entries(confidence)) {
    const keyNorm = normKey(key);
    const shouldCheck =
      !triggersForType ||
      Array.from(ruleFieldNorms).some(
        (rf) => keyNorm.includes(rf) || rf.includes(keyNorm)
      );

    if (!shouldCheck) {
      continue;
    }

    if (conf < thresholds.fieldConfidence) {
      confidenceOk = false;
      errors.push({
        field: key,
        message: `Field confidence below threshold (${conf.toFixed(2)})`,
      });
    }
  }
  checks.push({
    id: "field-confidence",
    label: "Field confidence validation",
    source: "document",
    status: confidenceOk ? "passed" : "failed",
    details: confidenceOk
      ? "All field confidence scores are above threshold"
      : "One or more field confidence scores are below threshold",
  });

  let nameMatchScore: number | null = null;
  if (options.expectedName && options.expectedName.trim() !== "") {
    const name = pickFirstString(extractedData, thresholds.nameFieldKeys);
    if (!name) {
      errors.push({
        field: "name",
        message: "Name not found in extracted data",
      });
    } else {
      nameMatchScore = computeNameMatchScorePercent(name, options.expectedName);
      if (nameMatchScore < thresholds.nameMatchPercent) {
        errors.push({
          field: "name",
          message: `Name match below threshold (${nameMatchScore}%)`,
        });
      }
    }
    checks.push({
      id: "name-match",
      label: "Name match check",
      source: "user_input",
      status:
        nameMatchScore !== null && nameMatchScore >= thresholds.nameMatchPercent
          ? "passed"
          : "failed",
      details:
        nameMatchScore === null
          ? "Name could not be compared"
          : `Score ${nameMatchScore}% (threshold ${thresholds.nameMatchPercent}%)`,
    });
  } else {
    checks.push({
      id: "name-match",
      label: "Name match check",
      source: "user_input",
      status: "skipped",
      details: "No input name provided by user",
    });
  }

  const dobStr = pickFirstString(extractedData, thresholds.dobFieldKeys);
  if (options.requireDob && !dobStr) {
    errors.push({
      field: "dob",
      message: "DOB required but missing in extraction",
    });
  }
  if (dobStr) {
    const d = validateDobIso(dobStr, thresholds.minAge);
    if (!d.valid) {
      errors.push({
        field: "dob",
        message: d.error ?? "Invalid DOB",
      });
    }
    checks.push({
      id: "dob-validation",
      label: "DOB format and age validation",
      source: "document",
      status: d.valid ? "passed" : "failed",
      details: d.valid
        ? `DOB valid and age >= ${thresholds.minAge}`
        : (d.error ?? "DOB validation failed"),
    });
  } else if (!options.requireDob) {
    checks.push({
      id: "dob-validation",
      label: "DOB format and age validation",
      source: "document",
      status: "skipped",
      details: "DOB not extracted",
    });
  }

  let faceMatchScore: number | null = null;
  if (options.selfiePath) {
    const r = await compareFaceImages(options.documentPath, options.selfiePath);
    if (r === null) {
      faceMatchScore = null;
    } else {
      faceMatchScore = r.score;
      if (r.error) {
        errors.push({ field: "face", message: r.error });
      } else if (r.score < thresholds.faceMatchScore) {
        errors.push({
          field: "face",
          message: `Face match below threshold (${(r.score * 100).toFixed(0)}%)`,
        });
      }
      checks.push({
        id: "face-match",
        label: "Face match check",
        source: "user_input",
        status:
          !r.error && r.score >= thresholds.faceMatchScore ? "passed" : "failed",
        details: r.error
          ? r.error
          : `Score ${(r.score * 100).toFixed(0)}% (threshold ${(thresholds.faceMatchScore * 100).toFixed(0)}%)`,
      });
    }
  } else {
    checks.push({
      id: "face-match",
      label: "Face match check",
      source: "user_input",
      status: "skipped",
      details: "No selfie uploaded by user",
    });
  }

  const shouldUseKeywordGating = !triggersForType;
  const keywordMatch = detectKeywords(normalizedType, ocrText);
  if (shouldUseKeywordGating && !keywordMatch) {
    errors.push({
      field: "keywords",
      message: "Document keywords not found",
    });
  }

  checks.push({
    id: "keyword-check",
    label: "Document keyword check",
    source: "document",
    status: triggersForType ? "skipped" : keywordMatch ? "passed" : "failed",
    details: triggersForType
      ? "Trigger-based validation is enabled for this document type"
      : keywordMatch
        ? "Expected keywords found in OCR text"
        : "Expected keywords not found",
  });

  const isValid = errors.length === 0;

  return {
    success: true,
    documentType: normalizedType,
    isValid,
    extractedData,
    confidence,
    faceMatchScore,
    nameMatchScore,
    checks,
    triggerResults,
    errors,
    message: buildMessage(errors, isValid),
  };
}

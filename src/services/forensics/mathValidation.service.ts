import type { ForensicSignal } from "./fileIntegrity.service";

function unwrap(value: unknown): unknown {
  if (value && typeof value === "object" && !Array.isArray(value) && "value" in value) {
    return (value as { value: unknown }).value;
  }
  return value;
}

function parseAmount(raw: unknown): number | null {
  const v = unwrap(raw);
  if (v == null || v === "") return null;
  if (typeof v === "number" && Number.isFinite(v)) return v;
  const s = String(v)
    .replace(/[, ]/g, "")
    .replace(/[₹$]/g, "")
    .replace(/[^\d.-]/g, "");
  if (!s) return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

function sumLineItems(items: unknown): number | null {
  const arr = unwrap(items);
  if (!Array.isArray(arr) || !arr.length) return null;
  let total = 0;
  let counted = 0;
  for (const item of arr) {
    const obj = unwrap(item);
    if (!obj || typeof obj !== "object") continue;
    const rec = obj as Record<string, unknown>;
    const amount =
      parseAmount(rec.amount) ??
      parseAmount(rec.value) ??
      parseAmount(rec.total) ??
      parseAmount(rec.debit) ??
      parseAmount(rec.credit);
    if (amount == null) continue;
    total += amount;
    counted++;
  }
  return counted ? total : null;
}

function nearlyEqual(a: number, b: number, tol = 1.0): boolean {
  return Math.abs(a - b) <= tol;
}

function pickField(data: Record<string, unknown>, keys: string[]): unknown {
  const map = new Map(
    Object.entries(data).map(([k, v]) => [k.toLowerCase().replace(/[^a-z0-9]/g, ""), v])
  );
  for (const key of keys) {
    const n = key.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (map.has(n)) return map.get(n);
  }
  return undefined;
}

/**
 * Business/math consistency checks (T041–T043).
 */
export function analyzeMathRules(
  documentType: string,
  extractedData: Record<string, unknown> | null | undefined
): ForensicSignal[] {
  if (!extractedData || typeof extractedData !== "object") return [];

  const data: Record<string, unknown> = { ...extractedData };
  const other = data.otherDetails;
  if (other && typeof other === "object" && !Array.isArray(other)) {
    Object.assign(data, other as Record<string, unknown>);
  }

  const dt = (documentType || "").toLowerCase();
  const signals: ForensicSignal[] = [];

  if (/salary|payslip|pay slip/.test(dt)) {
    const earningsSum = sumLineItems(pickField(data, ["earnings", "earning"]));
    const deductionsSum = sumLineItems(pickField(data, ["deductions", "deduction"]));
    const totalEarnings =
      parseAmount(pickField(data, ["totalEarnings", "grossSalary", "grossPay", "totalEarning"])) ??
      null;
    const totalDeductions =
      parseAmount(pickField(data, ["totalDeductions", "totalDeduction"])) ?? null;
    const net =
      parseAmount(
        pickField(data, ["netSalary", "netPay", "salaryAmountFigures", "takeHome"])
      ) ?? null;
    const gross =
      parseAmount(pickField(data, ["grossSalary", "totalEarnings", "grossPay"])) ?? totalEarnings;

    if (earningsSum != null && totalEarnings != null && !nearlyEqual(earningsSum, totalEarnings, 2)) {
      signals.push({
        code: "SALARY_EARNINGS_MISMATCH",
        threatCode: "T043",
        severity: "high",
        score: 20,
        status: "failed",
        title: "Earnings total mismatch",
        description: `Sum of earnings line items (${earningsSum.toFixed(2)}) does not match total earnings (${totalEarnings.toFixed(2)}).`,
        evidence: { earningsSum, totalEarnings },
      });
    }

    if (
      deductionsSum != null &&
      totalDeductions != null &&
      !nearlyEqual(deductionsSum, totalDeductions, 2)
    ) {
      signals.push({
        code: "SALARY_DEDUCTIONS_MISMATCH",
        threatCode: "T043",
        severity: "high",
        score: 20,
        status: "failed",
        title: "Deductions total mismatch",
        description: `Sum of deduction line items (${deductionsSum.toFixed(2)}) does not match total deductions (${totalDeductions.toFixed(2)}).`,
        evidence: { deductionsSum, totalDeductions },
      });
    }

    if (gross != null && totalDeductions != null && net != null) {
      const expected = gross - totalDeductions;
      if (!nearlyEqual(expected, net, 2)) {
        signals.push({
          code: "SALARY_NET_MISMATCH",
          threatCode: "T041",
          severity: "high",
          score: 22,
          status: "failed",
          title: "Net salary math mismatch",
          description: `Gross (${gross.toFixed(2)}) − deductions (${totalDeductions.toFixed(2)}) = ${expected.toFixed(2)}, but net is ${net.toFixed(2)}.`,
          evidence: { gross, totalDeductions, expectedNet: expected, net },
        });
      } else {
        signals.push({
          code: "SALARY_MATH_OK",
          threatCode: "T041",
          severity: "low",
          score: 0,
          status: "passed",
          title: "Salary math consistent",
          description: "Gross − deductions matches net salary within tolerance.",
          evidence: { gross, totalDeductions, net },
        });
      }
    } else if (!signals.length) {
      signals.push({
        code: "SALARY_MATH_INSUFFICIENT",
        threatCode: "T041",
        severity: "low",
        score: 0,
        status: "info",
        title: "Salary math not fully checkable",
        description: "Not enough numeric fields to validate earnings/deductions/net.",
      });
    }
  }

  if (/bank|statement|account statement/.test(dt)) {
    const opening = parseAmount(
      pickField(data, ["openingBalance", "opening", "previousBalance"])
    );
    const closing = parseAmount(
      pickField(data, ["closingBalance", "closing", "availableBalance"])
    );
    const credits = parseAmount(pickField(data, ["totalCredits", "credits", "totalCredit"]));
    const debits = parseAmount(pickField(data, ["totalDebits", "debits", "totalDebit"]));

    if (opening != null && closing != null && credits != null && debits != null) {
      const expected = opening + credits - debits;
      if (!nearlyEqual(expected, closing, 2)) {
        signals.push({
          code: "BANK_BALANCE_MISMATCH",
          threatCode: "T042",
          severity: "high",
          score: 22,
          status: "failed",
          title: "Bank balance mismatch",
          description: `Opening + credits − debits = ${expected.toFixed(2)}, but closing balance is ${closing.toFixed(2)}.`,
          evidence: { opening, credits, debits, expectedClosing: expected, closing },
        });
      } else {
        signals.push({
          code: "BANK_MATH_OK",
          threatCode: "T042",
          severity: "low",
          score: 0,
          status: "passed",
          title: "Bank balance consistent",
          description: "Opening + credits − debits matches closing balance.",
          evidence: { opening, credits, debits, closing },
        });
      }
    }
  }

  return signals;
}

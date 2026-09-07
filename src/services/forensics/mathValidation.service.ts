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
  if (!s || s === "-" || s === "." || s === "-.") return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

/** Prefer amount, else current+arrears (common payslip columns). */
function lineItemAmount(rec: Record<string, unknown>): number | null {
  const direct =
    parseAmount(rec.amount) ??
    parseAmount(rec.value) ??
    parseAmount(rec.total) ??
    parseAmount(rec.debit) ??
    parseAmount(rec.credit);
  if (direct != null) return direct;

  const current = parseAmount(rec.current);
  const arrears = parseAmount(rec.arrears);
  if (current != null && arrears != null) return current + arrears;
  if (current != null) return current;
  if (arrears != null) return arrears;
  return null;
}

function sumLineItems(items: unknown): {
  sum: number | null;
  counted: number;
  blankNamed: string[];
  namedCount: number;
} {
  const arr = unwrap(items);
  if (!Array.isArray(arr) || !arr.length) {
    return { sum: null, counted: 0, blankNamed: [], namedCount: 0 };
  }
  let total = 0;
  let counted = 0;
  const blankNamed: string[] = [];
  let namedCount = 0;

  for (const item of arr) {
    const obj = unwrap(item);
    if (!obj || typeof obj !== "object") continue;
    const rec = obj as Record<string, unknown>;
    const name = String(unwrap(rec.name) ?? unwrap(rec.label) ?? "")
      .trim()
      .toLowerCase();
    if (name) namedCount++;

    // Skip total/subtotal rows inside the array so we don't double-count.
    if (/^total\b|grand\s*total|net\s*pay/.test(name)) continue;

    const amount = lineItemAmount(rec);
    if (amount == null) {
      if (name) blankNamed.push(String(unwrap(rec.name) ?? unwrap(rec.label) ?? "").trim());
      continue;
    }
    total += amount;
    counted++;
  }

  return {
    sum: counted ? total : null,
    counted,
    blankNamed,
    namedCount,
  };
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

function sumNamedSalaryComponents(data: Record<string, unknown>): number | null {
  const parts = [
    parseAmount(pickField(data, ["basicSalary", "basic", "basicPay"])),
    parseAmount(pickField(data, ["hra", "houseRentAllowance"])),
    parseAmount(pickField(data, ["specialAllowance"])),
    parseAmount(pickField(data, ["conveyanceAllowance", "conveyance"])),
    parseAmount(pickField(data, ["otherAllowances", "otherAllowance"])),
  ].filter((n): n is number => n != null);
  if (!parts.length) return null;
  return parts.reduce((a, b) => a + b, 0);
}

function hasSalaryShape(data: Record<string, unknown>): boolean {
  return (
    pickField(data, [
      "earnings",
      "earning",
      "totalEarnings",
      "grossSalary",
      "netSalary",
      "netPay",
      "basicSalary",
      "salaryAmountFigures",
    ]) != null
  );
}

function hasBankShape(data: Record<string, unknown>): boolean {
  return (
    pickField(data, [
      "openingBalance",
      "closingBalance",
      "totalCredits",
      "totalDebits",
    ]) != null
  );
}

/**
 * Business/math + payslip layout consistency checks (T041–T044).
 * Runs when document type looks like salary/bank OR extracted fields look like them.
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

  const isSalaryDoc =
    /salary|payslip|pay[\s_-]?slip|wage/.test(dt) || hasSalaryShape(data);
  const isBankDoc =
    /bank|statement|account\s*statement/.test(dt) || hasBankShape(data);

  if (isSalaryDoc) {
    const earningsMeta = sumLineItems(pickField(data, ["earnings", "earning"]));
    const deductionsMeta = sumLineItems(pickField(data, ["deductions", "deduction"]));
    const namedComponentsSum = sumNamedSalaryComponents(data);

    const earningsSum =
      earningsMeta.sum != null
        ? earningsMeta.sum
        : namedComponentsSum;

    const totalEarnings =
      parseAmount(
        pickField(data, ["totalEarnings", "grossSalary", "grossPay", "totalEarning"])
      ) ?? null;
    const totalDeductions =
      parseAmount(pickField(data, ["totalDeductions", "totalDeduction"])) ?? null;
    const net =
      parseAmount(
        pickField(data, ["netSalary", "netPay", "salaryAmountFigures", "takeHome"])
      ) ?? null;
    const gross =
      parseAmount(pickField(data, ["grossSalary", "totalEarnings", "grossPay"])) ??
      totalEarnings;

    // Blank earning rows (e.g. Special Allowance removed) while a total exists.
    if (earningsMeta.blankNamed.length && totalEarnings != null) {
      signals.push({
        code: "SALARY_LAYOUT_ALIGNMENT",
        threatCode: "T044",
        severity: "high",
        score: 18,
        status: "failed",
        title: "Payslip layout / amount gap",
        description: `Earning line(s) have missing amounts (${earningsMeta.blankNamed.join(
          ", "
        )}) while Total Earnings is ${totalEarnings.toFixed(
          2
        )} — possible edit, font/alignment, or tampering.`,
        evidence: {
          blankNamed: earningsMeta.blankNamed,
          totalEarnings,
          earningsSum: earningsMeta.sum,
        },
      });
    }

    if (
      earningsSum != null &&
      totalEarnings != null &&
      !nearlyEqual(earningsSum, totalEarnings, 2)
    ) {
      signals.push({
        code: "SALARY_EARNINGS_MISMATCH",
        threatCode: "T043",
        severity: "high",
        score: 20,
        status: "failed",
        title: "Earnings total mismatch",
        description: `Sum of earnings line items (${earningsSum.toFixed(
          2
        )}) does not match total earnings (${totalEarnings.toFixed(2)}).`,
        evidence: {
          earningsSum,
          totalEarnings,
          blankNamed: earningsMeta.blankNamed,
          counted: earningsMeta.counted,
        },
      });
    }

    if (
      deductionsMeta.sum != null &&
      totalDeductions != null &&
      !nearlyEqual(deductionsMeta.sum, totalDeductions, 2)
    ) {
      signals.push({
        code: "SALARY_DEDUCTIONS_MISMATCH",
        threatCode: "T043",
        severity: "high",
        score: 20,
        status: "failed",
        title: "Deductions total mismatch",
        description: `Sum of deduction line items (${deductionsMeta.sum.toFixed(
          2
        )}) does not match total deductions (${totalDeductions.toFixed(2)}).`,
        evidence: {
          deductionsSum: deductionsMeta.sum,
          totalDeductions,
        },
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
          description: `Gross (${gross.toFixed(2)}) − deductions (${totalDeductions.toFixed(
            2
          )}) = ${expected.toFixed(2)}, but net is ${net.toFixed(2)}.`,
          evidence: { gross, totalDeductions, expectedNet: expected, net },
        });
      } else if (!signals.some((s) => s.status === "failed")) {
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

  if (isBankDoc) {
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
          description: `Opening + credits − debits = ${expected.toFixed(
            2
          )}, but closing balance is ${closing.toFixed(2)}.`,
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

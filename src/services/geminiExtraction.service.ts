import fs from "fs";
import path from "path";
import sharp from "sharp";
import { GoogleGenerativeAI } from "@google/generative-ai";
import "dotenv/config";
import { parseJsonObjectFromModelText } from "../utils/jsonExtract.util";
import { normalizeExtractedPayload } from "../utils/extractionNormalize.util";

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || "");

/* ---------------- IMAGE FIX (WEBP ISSUE) ---------------- */
async function prepareImage(filePath: string): Promise<string> {
  const ext = path.extname(filePath).toLowerCase();

  if (ext === ".webp") {
    const newPath = filePath.replace(".webp", ".png");
    await sharp(filePath).png().toFile(newPath);
    return newPath;
  }

  return filePath;
}


function getTypeSpecificPrompt(documentTypeHint: string): string {
  const normalized = (documentTypeHint || "").toLowerCase().trim();

  const promptByType: Array<{ matches: string[]; prompt: string }> = [
    {
      matches: ["aadhaar", "aadhar"],
      // prompt: `
      //     Aadhaar-specific extraction:
      //     - aadhaarNumber (12 digits)
      //     - name
      //     - dob or yearOfBirth
      //     - gender
      //     - address
      //     - mobileNumber (if available)
      // `,
      // prompt: `
      //     Aadhaar-specific extraction:
      //     - aadhaarNumber (12 digits)
      //     - name
      //     - dob or yearOfBirth
      //     - gender
      //     - address

      //     Validation checks:
      //     - photoAvailable (true/false)
      //     - qrCodeAvailable (true/false) (secure QR should be present in newer Aadhaar)
      //     - aadhaarFormatValid (true/false) (12 digits structure)
      //     - maskedAadhaar (true/false) (XXXX-XXXX-1234 format)
      //     - genderMatch (true/false) (text clearly shows gender)
      //     - dobOrYearOnly (value should be "dob", "year", or null)
      //     - addressAvailable (true/false)
      //     - uidaiNameAvailable (true/false) ("Unique Identification Authority of India")
      //     - govtLogoAvailable (true/false)

      //     Security checks:
      //     - qrReadable (true/false) (if QR exists, appears scannable)

      //     Tampering detection:
      //     - tamperingDetected (true/false)
      //     - tamperingType (array or null)

      //     Possible tamperingType values:
      //     - "photo_pasted"
      //     - "text_overwrite"
      //     - "font_mismatch"
      //     - "blurred_text"
      //     - "qr_missing_or_fake"
      //     - "alignment_issue"

      //     Rules:
      //     - Do NOT guess
      //     - If tamperingDetected = false → tamperingType = null
      //     - If unsure → false/null
      // `,
      prompt: `
        Aadhaar extraction:
        - aadhaarNumber
        - name
        - dob or yearOfBirth
        - gender
        - address

        Style required for:
        - aadhaarNumber (bold)
        - name (medium/large)

        Validation:
        - photoAvailable
        - qrCodeAvailable
        - aadhaarFormatValid
        - maskedAadhaar
        - genderMatch
        - dobOrYearOnly
        - addressAvailable
        - uidaiNameAvailable
        - govtLogoAvailable

        Security:
        - qrReadable

        Tampering:
        - tamperingDetected
        - tamperingType

        Possible tamperingType:
        - photo_pasted, text_overwrite, font_mismatch, blurred_text,
          qr_missing_or_fake, alignment_issue

        Rules:
        - do not assume missing QR = tampering
      `
    },
    {
      matches: ["pan"],
      // prompt: `
      //     PAN-specific extraction:
      //     - panNumber (format: AAAAA9999A)
      //     - name
      //     - fatherName
      //     - dob
      // `,
      //   prompt: `
      //     PAN-specific extraction:
      //     - panNumber (format: AAAAA9999A)
      //     - name
      //     - fatherName
      //     - dob

      //     Validation checks (strict yes/no or true/false based only on visible content):
      //     - photoAvailable (true/false)
      //     - signatureAvailable (true/false)
      //     - qrCodeAvailable (true/false)
      //     - isDobOrIncorporationDate (value should be "dob", "incorporationDate", or null)
      //     - issueDateAvailable (true/false)
      //     - issueDate (value if visible else null)
      //     - incomeTaxDepartmentNameAvailable (true/false)
      //     - govtSymbolAvailable (true/false)

      //     Tampering detection:
      //     - tamperingDetected (true/false)
      //     - tamperingType (array of strings OR null)

      //     Possible tamperingType values:
      //     - "photo_pasted"
      //     - "signature_mismatch"
      //     - "text_overwrite"
      //     - "font_mismatch"
      //     - "alignment_issue"
      //     - "blurred_text"
      //     - "cut_paste_marks"
      //     - "qr_mismatch"
      //     - "number_modified"

      //     Rules:
      //     - If tamperingDetected = false → tamperingType must be null
      //     - If tamperingDetected = true → include all visible issues in tamperingType array
      //     - Do NOT guess
      //     - Only include clearly visible issues
      //     - If unsure → tamperingDetected = false and tamperingType = null
      // `,
      prompt: `
        PAN Card extraction:
        - panNumber
        - name
        - fatherName
        - dob

        Style required for:
        - panNumber (bold, uppercase)
        - name (large font, uppercase)

        Validation:
        - photoAvailable
        - signatureAvailable
        - qrCodeAvailable
        - isDobOrIncorporationDate
        - issueDateAvailable
        - issueDate
        - incomeTaxDepartmentNameAvailable
        - govtSymbolAvailable

        Tampering:
        - tamperingDetected
        - tamperingType

        Possible tamperingType:
        - photo_pasted, signature_mismatch, text_overwrite, font_mismatch,
          alignment_issue, blurred_text, cut_paste_marks, qr_mismatch, number_modified

        Rules:
        - style only for text fields
        - tamperingType null if no tampering
      `
    },
    {
      matches: ["voter"],
      // prompt: `
      //     Voter Card extraction:
      //     - voterId
      //     - name
      //     - fatherOrHusbandName
      //     - dob or age
      //     - gender
      //     - address
      // `,
      // prompt: `
      //     Voter ID extraction:
      //     - voterId (EPIC number)
      //     - name
      //     - fatherOrHusbandName
      //     - dob or age
      //     - gender
      //     - address

      //     Validation checks:
      //     - photoAvailable (true/false)
      //     - epicFormatValid (true/false) (usually 3 letters + 7 digits)
      //     - genderAvailable (true/false)
      //     - ageOrDob (value should be "age", "dob", or null)
      //     - addressAvailable (true/false)
      //     - electionCommissionNameAvailable (true/false)
      //     - govtLogoAvailable (true/false)

      //     Security checks:
      //     - hologramOrSealVisible (true/false) (if visible)

      //     Tampering detection:
      //     - tamperingDetected (true/false)
      //     - tamperingType (array or null)

      //     Possible tamperingType values:
      //     - "photo_pasted"
      //     - "text_overwrite"
      //     - "font_mismatch"
      //     - "blurred_text"
      //     - "id_number_modified"
      //     - "alignment_issue"

      //     Rules:
      //     - Only mark true if clearly visible
      //     - If tamperingDetected = false → tamperingType = null
      // `,
      prompt: `
        Voter ID extraction:
        - voterId
        - name
        - fatherOrHusbandName
        - dob or age
        - gender
        - address

        Style required for:
        - voterId (bold uppercase)
        - name (medium)

        Validation:
        - photoAvailable
        - epicFormatValid
        - genderAvailable
        - ageOrDob
        - addressAvailable
        - electionCommissionNameAvailable
        - govtLogoAvailable

        Security:
        - hologramOrSealVisible

        Tampering:
        - tamperingDetected
        - tamperingType

        Possible tamperingType:
        - photo_pasted, text_overwrite, font_mismatch,
          blurred_text, id_number_modified, alignment_issue
      `
    },
    {
      matches: ["passport"],
      // prompt: `
      //     Passport extraction:
      //     - passportNumber
      //     - surname
      //     - givenName
      //     - nationality
      //     - dob
      //     - issueDate
      //     - expiryDate
      //     - placeOfIssue
      // `,
      // prompt: `
      //     Passport extraction:
      //     - passportNumber
      //     - surname
      //     - givenName
      //     - nationality
      //     - dob
      //     - issueDate
      //     - expiryDate
      //     - placeOfIssue

      //     Validation checks:
      //     - mrzAvailable (true/false) (Machine Readable Zone at bottom)
      //     - passportFormatValid (true/false) (alphanumeric format)
      //     - nationalityAvailable (true/false)
      //     - dobAvailable (true/false)
      //     - expiryDateAvailable (true/false)
      //     - issuingAuthorityAvailable (true/false)
      //     - govtEmblemAvailable (true/false)

      //     Security checks:
      //     - mrzReadable (true/false)
      //     - photoAvailable (true/false)
      //     - signatureAvailable (true/false)
      //     - hologramVisible (true/false)

      //     Tampering detection:
      //     - tamperingDetected (true/false)
      //     - tamperingType (array or null)

      //     Possible tamperingType values:
      //     - "photo_pasted"
      //     - "mrz_mismatch"
      //     - "text_overwrite"
      //     - "font_mismatch"
      //     - "blurred_text"
      //     - "page_damage"
      //     - "number_modified"

      //     Rules:
      //     - MRZ must be clearly visible to mark true
      //     - If tamperingDetected = false → tamperingType = null
      // `,
      prompt: `
        Passport extraction:
        - passportNumber
        - surname
        - givenName
        - nationality
        - dob
        - issueDate
        - expiryDate
        - placeOfIssue

        Style required for:
        - passportNumber (bold)
        - MRZ (monospace, small font)

        Validation:
        - mrzAvailable
        - passportFormatValid
        - nationalityAvailable
        - dobAvailable
        - expiryDateAvailable
        - issuingAuthorityAvailable
        - govtEmblemAvailable

        Security:
        - mrzReadable
        - photoAvailable
        - signatureAvailable
        - hologramVisible

        Tampering:
        - tamperingDetected
        - tamperingType

        Possible tamperingType:
        - photo_pasted, mrz_mismatch, text_overwrite,
          font_mismatch, blurred_text, page_damage, number_modified
      `
    },
    {
      matches: ["driving"],
      // prompt: `
      //     Driving License extraction:
      //     - licenseNumber
      //     - name
      //     - dob
      //     - address
      //     - issueDate
      //     - validityDate
      // `,
      // prompt: `
      //     Driving License extraction:
      //     - licenseNumber
      //     - name
      //     - dob
      //     - address
      //     - issueDate
      //     - validityDate

      //     Validation checks:
      //     - licenseFormatValid (true/false) (state code + digits)
      //     - photoAvailable (true/false)
      //     - dobAvailable (true/false)
      //     - validityAvailable (true/false)
      //     - issuingAuthorityAvailable (true/false)
      //     - rtoNameAvailable (true/false)
      //     - addressAvailable (true/false)
      //     - bloodGroupAvailable (true/false)

      //     Security checks:
      //     - smartCardFormat (true/false) (new DL cards)
      //     - qrCodeAvailable (true/false)
      //     - chipVisible (true/false) (if smart card)

      //     Tampering detection:
      //     - tamperingDetected (true/false)
      //     - tamperingType (array or null)

      //     Possible tamperingType values:
      //     - "photo_pasted"
      //     - "text_overwrite"
      //     - "font_mismatch"
      //     - "blurred_text"
      //     - "qr_missing_or_fake"
      //     - "number_modified"
      //     - "alignment_issue"

      //     Rules:
      //     - If tamperingDetected = false → tamperingType = null
      //     - Do NOT assume missing features = tampering
      // `,
      prompt: `
        Driving License extraction:
        - licenseNumber
        - name
        - dob
        - address
        - issueDate
        - validityDate

        Style required for:
        - licenseNumber (bold)
        - name (medium/large)

        Validation:
        - licenseFormatValid
        - photoAvailable
        - dobAvailable
        - validityAvailable
        - issuingAuthorityAvailable
        - rtoNameAvailable
        - addressAvailable
        - bloodGroupAvailable

        Security:
        - smartCardFormat
        - qrCodeAvailable
        - chipVisible

        Tampering:
        - tamperingDetected
        - tamperingType

        Possible tamperingType:
        - photo_pasted, text_overwrite, font_mismatch,
          blurred_text, qr_missing_or_fake, number_modified, alignment_issue

        Rules:
        - missing QR does not mean tampering
      `
    },
    {
      matches: ["gst"],
      prompt: `
          GST extraction:
          - gstNumber
          - businessName
          - proprietorName
          - registrationDate
          - address
      `,
    },
    {
      matches: ["itr"],
      prompt: `
        ITR extraction:
        - pan
        - assessmentYear
        - totalIncome
        - taxPaid
        - refundAmount
      `,
    },
    {
      matches: ["bank statement"],
      prompt: `
        Bank Statement extraction:
        - accountHolderName
        - accountNumber
        - ifscCode
        - bankName
        - statementPeriod
        - openingBalance
        - closingBalance
        - transactions (list if possible)
      `,
    },
    {
      matches: ["salary"],
      prompt: `
        Salary Slip extraction:
        - employerName
        - employerAddress (if present)
        - employerGstin (if present)
        - employerCin (if present)
        - employerPfCode (if present)
        - employerEsicCode (if present)
        -
        - employeeName
        - employeeId
        - employeeCode (if present)
        - department (if present)
        - designation (if present)
        - dateOfJoining (if present)
        - payPeriod (month/year or from-to dates)
        - payDate (if present)
        -
        - pan (if present)
        - uan (if present)
        - pfNumber (if present)
        - esicNumber (if present)
        -
        - bankName (if present)
        - bankAccountNumber (if present)
        - ifscCode (if present)
        -
        - workingDays (if present)
        - daysPaid (if present)
        - leaves (if present)
        - lopDays (loss of pay, if present)
        -
        - earnings (array of { name, arrears, current, amount })
        - deductions (array of { name, amount })
        - reimbursements (array of { name, amount } if present)
        -
        - totalEarnings (if present)
        - totalDeductions (if present)
        - grossSalary (if present)
        - netSalary
        -
        - basicSalary (if present)
        - hra (if present)
        - conveyanceAllowance (if present)
        - specialAllowance (if present)
        - otherAllowances (if present)
        -
        - pfEmployeeContribution (if present)
        - pfEmployerContribution (if present)
        - professionalTaxAmount (if present)
        - incomeTaxAmount (if present)
        - healthInsurancePremium (if present)
        -
        - salaryAmountFigures (if present)
        - salaryAmountWords (if present)
        -
        - signaturePresent (true/false if visible)
        - companySealPresent (true/false if visible)
      `,
    },
    {
      matches: ["form 16"],
      prompt: `
        Form 16 extraction:
        - tan
        - deductorName
        - employeeName
        - pan
        - assessmentYear
        - totalSalary
        - taxDeducted
      `,
    },
    {
      matches: ["trade"],
      prompt: `
        Trade License extraction:
        - licenseNumber
        - businessName
        - issuedBy
        - issueDate
        - expiryDate
      `,
    },
    {
      matches: ["financial"],
      prompt: `
        Financial Document extraction:
        - documentType
        - totalAmount
        - dates
        - institutionName
        - accountDetails
      `,
    },
    {
      matches: ["salaried profile"],
      prompt: `
        Salaried Profile extraction:
        - employerName
        - designation
        - monthlyIncome
        - experienceYears
        - companyEmailDomain
      `,
    },
    {
      matches: ["self-employed"],
      prompt: `
      Self-Employed Profile extraction:
      - businessName
      - ownerName
      - annualIncome
      - gstNumber
      - businessAddress
      `,
    },
  ];

  const match = promptByType.find((entry) =>
    entry.matches.some((m) => normalized.includes(m))
  );

  return match ? match.prompt : `
      General extraction:
      - Extract all visible key-value pairs from the document.
      - Always include: documentType and otherDetails.
      `;
}


/* ---------------- MIME TYPE ---------------- */
function getMimeType(filePath: string, fallbackMimeType?: string): string {
  if (fallbackMimeType && fallbackMimeType.trim() !== "") {
    return fallbackMimeType;
  }

  const ext = path.extname(filePath).toLowerCase();

  if (ext === ".pdf") return "application/pdf";
  if (ext === ".png") return "image/png";

  return "image/jpeg";
}

function buildStructuredExtractionPrompt(documentTypeHint: string): string {
  const typeSpecificPrompt = getTypeSpecificPrompt(documentTypeHint);

  return `
    Extract structured data from document.

    Return ONLY valid minified JSON.

    Rules:
    - No explanation
    - No markdown
    - No guessing
    - Use null if not visible
    - Keep exact values from image

    Format:
    {
      "documentType": "",
      "fieldName": {
        "value": "",
        "confidence": 0,
        "style": {
          "fontStyle": "",
          "fontColor": "",
          "fontSize": "",
          "fontFamily": ""
        }
      }
    }

    Style Rules:
    - Apply style ONLY for text fields (name, number, etc.)
    - DO NOT apply style for boolean fields
    - fontStyle: "bold", "italic", "normal", "uppercase"
    - fontColor: basic colors (black, blue, red)
    - fontSize: "small", "medium", "large"
    - fontFamily: detect if possible (serif, sans-serif, monospace, printed, handwritten)
    - If not clear → set null

    Confidence Rules:
    - 0 to 1 scale
    - High clarity → 0.9+
    - Medium → 0.6–0.8
    - Low → below 0.5

    Mandatory:
    - documentType
    - otherDetails (object)

    Document Type: ${documentTypeHint}

    ${typeSpecificPrompt}
  `;
}

/* ---------------- MAIN PROMPT (OPTIMIZED ONLY) ---------------- */
// function buildStructuredExtractionPrompt(documentTypeHint: string): string {
//   const typeSpecificPrompt = getTypeSpecificPrompt(documentTypeHint);

//   return `
//       Extract structured data from document.

//       Return ONLY valid minified JSON.

//       Rules:
//       - No explanation
//       - No markdown
//       - No guessing
//       - Use null if not visible
//       - Keep exact values from image

//       Format:
//       {
//         "documentType": "",
//         "fieldName": { "value": "", "confidence": 0 }
//       }

//       Mandatory:
//       - documentType
//       - otherDetails (object)

//       Document Type: ${documentTypeHint}

//       ${typeSpecificPrompt}
//       `;
// }

/* ---------------- TYPES ---------------- */
export interface StructuredExtractionResult {
  data: Record<string, unknown>;
  fieldConfidence: Record<string, number>;
  rawText: string;
}

/* ---------------- RETRY ---------------- */
function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

function isRetriableGeminiError(err: any): boolean {
  return [429, 500, 502, 503, 504].includes(err?.status);
}

/* ---------------- MODEL ---------------- */
function getFallbackModelNames(): string[] {
  return [
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite" // safer backup if available
  ];
}

/* ---------------- GEMINI CALL ---------------- */
async function generateContentWithRetryAndFallback(args: {
  modelNames: string[];
  prompt: string;
  mimeType: string;
  base64Image: string;
}): Promise<string> {
  const { modelNames, prompt, mimeType, base64Image } = args;

  let lastError: any = null;

  for (const modelName of modelNames) {
    const model = genAI.getGenerativeModel({ model: modelName });

    for (let attempt = 1; attempt <= 3; attempt++) {
      let timeout: ReturnType<typeof setTimeout> | null = null;
      try {
        console.log(`Model: ${modelName}, Attempt: ${attempt}`);

        const controller = new AbortController();
        timeout = setTimeout(() => controller.abort(), 15000);

        const result = await model.generateContent([
          prompt,
          { inlineData: { mimeType, data: base64Image } },
        ]);

        if (timeout) clearTimeout(timeout);

        return result.response.text();
      } catch (err: any) {
        if (timeout) clearTimeout(timeout);

        lastError = err;

        console.log("Error:", err?.status || err?.message);

        // ❌ DO NOT retry for non-retriable errors
        if (!isRetriableGeminiError(err)) {
          throw err;
        }

        // ⏳ exponential backoff (important)
        const delay = Math.min(4000, 500 * Math.pow(2, attempt));
        console.log(`Retrying after ${delay}ms...`);
        await sleep(delay);
      }
    }
  }

  // ✅ FINAL FALLBACK (VERY IMPORTANT)
  console.log("⚠️ Gemini failed completely, returning fallback response");

  return JSON.stringify({
    documentType: "unknown",
    otherDetails: {
      error: "Gemini unavailable (503)",
    },
  });
}

/* ---------------- MAIN FUNCTION ---------------- */
export async function extractStructuredDataFromDocument(
  filePath: string,
  documentTypeHint: string,
  mimeTypeHint?: string
): Promise<StructuredExtractionResult | null> {
  try {
    let absolutePath = path.resolve(filePath);

    console.log("Original:", absolutePath);

    // 🔥 FIX WEBP
    absolutePath = await prepareImage(absolutePath);

    console.log("Processed:", absolutePath);

    const imageBuffer = await fs.promises.readFile(absolutePath);
    const base64Image = imageBuffer.toString("base64");
    const mimeType = getMimeType(absolutePath, mimeTypeHint);

    const prompt = buildStructuredExtractionPrompt(documentTypeHint);

    const rawText = await generateContentWithRetryAndFallback({
      modelNames: getFallbackModelNames(),
      prompt,
      mimeType,
      base64Image,
    });

    const parsed = parseJsonObjectFromModelText(rawText);
    const { flat, confidence } = normalizeExtractedPayload(parsed);

    return { data: flat, fieldConfidence: confidence, rawText };
  } catch (error) {
    console.log("❌ ERROR:", error);

    return {
      data: {},
      fieldConfidence: {},
      rawText: "Extraction failed",
    };
  }
}
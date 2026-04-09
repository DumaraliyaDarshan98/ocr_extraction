export const detectKeywords = (type: string, text: string) => {
    const normalizedType = (type || "").toLowerCase().replace(/[\s-]+/g, "_");

    const keywords: any = {

        aadhaar: [
            "government of india",
            "aadhaar",
            "uidai"
        ],

        pan: [
            "income tax department",
            "permanent account number"
        ],

        passport: [
            "passport",
            "republic of india"
        ],

        driving_license: [
            "driving licence",
            "transport department"
        ],
        voter_card: [
            "election commission of india",
            "electors photo identity card",
            "voter"
        ],
        financial: [
            "profit and loss",
            "balance sheet",
            "financial"
        ],
        itr: [
            "income tax return",
            "income tax",
            "itr",
            "acknowledgement"
        ],
        gst: [
            "goods and services tax",
            "gstin",
            "gst",
            "gst return",
            "taxpayer"
        ],
        salary_slip: [
            "salary slip",
            "gross salary",
            "net salary",
            "employee",
            "salary"
        ],
        salaried_profile: [
            "salaried",
            "employment",
            "employer",
            "designation",
            "monthly income",
            "salary"
        ],
        bank_statement: [
            "bank statement",
            "account number",
            "ifsc",
            "micr",
            "balance",
            "cheque",
            "bank"
        ],
        self_employed_profile: [
            "self-employed",
            "self employed",
            "form 16",
            "tan",
            "tax deduction",
            "collection account"
        ],
        form_16: [
            "form 16",
            "tan",
            "tax deduction",
            "deduction & collection"
        ],
        trade_license: [
            "trade license",
            "trade licence",
            "municipal",
            "authority"
        ]
    };

    const docKeywords = keywords[normalizedType];

    if (!docKeywords) return false;

    return docKeywords.some((k: string) => text.includes(k));
};
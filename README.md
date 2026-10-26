# OCR Extraction Service

Express + TypeScript sidecar for Indian KYC document identify, extract, and verify. Consumed by `swarajya_finance_backend` (`OcrService`).

## Stack

- Express 5, TypeScript (`ts-node-dev`)
- Google Gemini (`@google/generative-ai`) for identify / extract
- Optional OpenAI authenticity path (`USE_OPENAI=true`)
- Tesseract.js fallback (images), Sharp/Jimp, face-api (optional face match)
- Multer uploads under `src/uploads/`

## Quick start

```bash
cp .env.example .env   # or create .env with GEMINI_API_KEY
npm install
npm run dev            # listens on http://localhost:3300
```

## Environment

| Key | Purpose |
|-----|---------|
| `GEMINI_API_KEY` | Required for Gemini identify/extract |
| `OCR_SERVICE_API_KEY` | Shared secret with Nest (`X-OCR-API-Key`). Required in production |
| `OCR_RATE_LIMIT_MAX` / `OCR_RATE_LIMIT_WINDOW_MS` | Per-IP rate limit (default 60/min) |
| `PORT` | Listen port (default **3300**) |
| `OPENAI_API_KEY` / `USE_OPENAI` | Optional authenticity scoring |
| `TRIGGER_CONFIG_PATH` | Optional path to trigger JSON folder |

## Health

| Method | Path | Notes |
|--------|------|--------|
| GET | `/health` | Liveness |
| GET | `/ready` | Requires Gemini key |

All `/api/document/*` routes require API key (when configured) + rate limit.

## API (`/api/document`)

| Method | Path | Input | Behavior |
|--------|------|--------|----------|
| POST | `/identify` | multipart `file` | Document type + confidence |
| POST | `/extract-simple` | multipart `file` + `documentType` | Structured fields (+ text fallback) |
| POST | `/verify` | multipart `file`, optional `selfie`; body: `documentType`, optional name/DOB/RCU triggers/forensics | Full KYC / RCU verify response |
| POST | `/validate` | JSON `{ documentType, extractedData }` | Trigger-engine validation only |

### Document types (identify allow-list)

PAN, Aadhaar, Voter Card, Driving License, Passport, Salary Slip, Form 16, Bank Statement, ITR, GST, Trade License, Address Proof, Agreement, Ownership Deed, Other.

### Verify modes

1. **RCU** — when `triggers` and/or `useRcuTriggers` is set: Gemini extraction + RCU evaluation + forensics.
2. **Standard** — Gemini + JSON trigger configs (or legacy checks) + optional name / DOB / face match.

## Scripts

| Script | Purpose |
|--------|---------|
| `npm run dev` | Dev server |
| `npm run import-triggers` | Import triggers from Excel into config JSON |

## Integration

Backend default: `OCR_SERVICE_URL=http://localhost:3300`.

- OCR cases: identify → RCU triggers → verify (with forensic configs)
- Simple tool: `POST /api/verification-requests/ocr/extract-simple` → this service’s verify/extract path via backend proxy

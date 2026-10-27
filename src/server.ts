import "dotenv/config";
import app from "./app";

const PORT = Number(process.env.PORT || process.env.OCR_PORT || 3300);

const server = app.listen(PORT, () => {
  console.log(`OCR extraction service running on ${PORT}`);
  if (!process.env.OCR_SERVICE_API_KEY) {
    console.warn(
      "[ocr] OCR_SERVICE_API_KEY is not set — API key auth is disabled (dev only).",
    );
  }
  const geminiKey = String(
    process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || "",
  ).trim();
  if (!geminiKey) {
    console.warn(
      "[ocr] GEMINI_API_KEY is NOT set — identify/verify will use local Tesseract fallbacks only. Add a Google AI Studio key to ocr_extraction/.env for full Aadhaar/PAN AI extraction.",
    );
  } else {
    console.log(`[ocr] Gemini configured (key length=${geminiKey.length})`);
  }
});

server.on("error", (err: NodeJS.ErrnoException) => {
  if (err && err.code === "EADDRINUSE") {
    console.error(
      `Port ${PORT} is already in use. Stop the existing server and try again.`,
    );
    process.exit(1);
  }
  console.error("Server error:", err);
  process.exit(1);
});

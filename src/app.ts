import express from "express";
import cors from "cors";
import documentRoutes from "./routes/document.routes";
import { apiKeyAuth } from "./middleware/api-key.middleware";
import { rateLimit } from "./middleware/rate-limit.middleware";

const app = express();

app.use(cors());
app.use(express.json({ limit: "2mb" }));

app.get("/health", (_req, res) => {
  const hasGemini = Boolean(
    process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY,
  );
  res.status(200).json({
    ok: true,
    service: "ocr_extraction",
    timestamp: new Date().toISOString(),
    geminiConfigured: hasGemini,
  });
});

app.get("/ready", (_req, res) => {
  const hasGemini = Boolean(
    process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY,
  );
  if (!hasGemini) {
    res.status(503).json({
      ok: false,
      ready: false,
      message: "GEMINI_API_KEY not configured",
    });
    return;
  }
  res.status(200).json({ ok: true, ready: true });
});

app.use("/api/document", rateLimit, apiKeyAuth, documentRoutes);

export default app;

import type { Request, Response, NextFunction } from "express";

/**
 * Shared-secret auth between Nest backend and this OCR sidecar.
 * Set OCR_SERVICE_API_KEY on both services (same value).
 * When unset in development, requests are allowed with a warning.
 */
export function apiKeyAuth(req: Request, res: Response, next: NextFunction): void {
  const expected = String(process.env.OCR_SERVICE_API_KEY || "").trim();
  if (!expected) {
    if (process.env.NODE_ENV === "production") {
      res.status(503).json({
        success: false,
        message: "OCR_SERVICE_API_KEY is not configured",
      });
      return;
    }
    next();
    return;
  }

  const provided =
    String(req.headers["x-ocr-api-key"] || "").trim() ||
    String(req.headers["authorization"] || "")
      .replace(/^Bearer\s+/i, "")
      .trim();

  if (!provided || provided !== expected) {
    res.status(401).json({ success: false, message: "Unauthorized OCR request" });
    return;
  }
  next();
}

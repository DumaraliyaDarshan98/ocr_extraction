import type { Request, Response, NextFunction } from "express";

type Bucket = { count: number; resetAt: number };

const buckets = new Map<string, Bucket>();

const WINDOW_MS = Number(process.env.OCR_RATE_LIMIT_WINDOW_MS || 60_000);
const MAX_REQ = Number(process.env.OCR_RATE_LIMIT_MAX || 60);

/**
 * Simple in-memory rate limiter (per IP). Fine for a single OCR instance.
 */
export function rateLimit(req: Request, res: Response, next: NextFunction): void {
  const key =
    String(req.headers["x-forwarded-for"] || "")
      .split(",")[0]
      .trim() ||
    req.ip ||
    req.socket?.remoteAddress ||
    "unknown";

  const now = Date.now();
  let bucket = buckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    bucket = { count: 0, resetAt: now + WINDOW_MS };
    buckets.set(key, bucket);
  }

  bucket.count += 1;
  res.setHeader("X-RateLimit-Limit", String(MAX_REQ));
  res.setHeader(
    "X-RateLimit-Remaining",
    String(Math.max(0, MAX_REQ - bucket.count)),
  );

  if (bucket.count > MAX_REQ) {
    res.status(429).json({
      success: false,
      message: "Too many OCR requests. Try again shortly.",
    });
    return;
  }
  next();
}

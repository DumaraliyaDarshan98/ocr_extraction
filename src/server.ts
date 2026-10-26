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

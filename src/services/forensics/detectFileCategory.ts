export type ForensicFileCategory = "PDF" | "IMAGE" | "DOC" | "ZIP";

/**
 * Detect forensic file-type category from path + mime.
 * IMAGE covers jpeg/png/webp/gif/bmp/tiff/heic/etc.
 */
export function detectForensicFileCategory(
  filePath?: string | null,
  mimeType?: string | null
): ForensicFileCategory | null {
  const name = String(filePath || "").toLowerCase();
  const mime = String(mimeType || "").toLowerCase();
  const ext = name.includes(".") ? name.split(".").pop() || "" : "";

  if (mime.includes("pdf") || ext === "pdf") return "PDF";

  if (
    mime.startsWith("image/") ||
    ["jpg", "jpeg", "jfif", "png", "webp", "gif", "bmp", "tif", "tiff", "heic", "heif", "svg"].includes(
      ext
    )
  ) {
    return "IMAGE";
  }

  if (
    mime.includes("msword") ||
    mime.includes("wordprocessingml") ||
    mime.includes("ms-excel") ||
    mime.includes("spreadsheetml") ||
    mime.includes("ms-powerpoint") ||
    mime.includes("presentationml") ||
    mime.includes("rtf") ||
    mime.includes("opendocument") ||
    ["doc", "docx", "rtf", "odt", "xls", "xlsx", "ppt", "pptx", "ods", "odp"].includes(ext)
  ) {
    return "DOC";
  }

  if (
    mime.includes("zip") ||
    mime.includes("x-rar") ||
    mime.includes("x-7z") ||
    mime.includes("x-tar") ||
    mime.includes("gzip") ||
    ["zip", "rar", "7z", "tar", "gz", "tgz"].includes(ext)
  ) {
    return "ZIP";
  }

  return null;
}

import type { ForensicSignal } from "./fileIntegrity.service";
import fs from "fs";
import path from "path";
import sharp from "sharp";

function detectImageMagic(buf: Buffer): string | null {
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "jpeg";
  if (
    buf.length >= 8 &&
    buf[0] === 0x89 &&
    buf[1] === 0x50 &&
    buf[2] === 0x4e &&
    buf[3] === 0x47
  ) {
    return "png";
  }
  if (
    buf.length >= 12 &&
    buf.subarray(0, 4).toString("ascii") === "RIFF" &&
    buf.subarray(8, 12).toString("ascii") === "WEBP"
  ) {
    return "webp";
  }
  if (
    buf.length >= 6 &&
    (buf.subarray(0, 6).toString("ascii") === "GIF87a" ||
      buf.subarray(0, 6).toString("ascii") === "GIF89a")
  ) {
    return "gif";
  }
  if (buf.length >= 2 && buf[0] === 0x42 && buf[1] === 0x4d) return "bmp";
  return null;
}

const EDITOR_SIGNATURES: Array<{ re: RegExp; label: string }> = [
  { re: /Adobe Photoshop/i, label: "Adobe Photoshop" },
  { re: /GIMP/i, label: "GIMP" },
  { re: /Paint\.NET/i, label: "Paint.NET" },
  { re: /Microsoft Paint/i, label: "Microsoft Paint" },
  { re: /Affinity Photo/i, label: "Affinity Photo" },
  { re: /Pixelmator/i, label: "Pixelmator" },
  { re: /Photopea/i, label: "Photopea" },
  { re: /Canva/i, label: "Canva" },
  { re: /Snipping Tool/i, label: "Snipping Tool" },
  { re: /Snip & Sketch/i, label: "Snip & Sketch" },
  { re: /Screenshot/i, label: "Screenshot tool" },
  { re: /ImageMagick/i, label: "ImageMagick" },
  { re: /Corel/i, label: "CorelDRAW/PHOTO-PAINT" },
  { re: /Adobe Illustrator/i, label: "Adobe Illustrator" },
  { re: /Inkscape/i, label: "Inkscape" },
  { re: /Photoshop/i, label: "Photoshop" },
  { re: /Lightroom/i, label: "Lightroom" },
];

function findEditorSignatures(buf: Buffer): string[] {
  // latin1 keeps binary searchable without throwing on non-utf8
  const text =
    buf.length > 2_000_000
      ? buf.subarray(0, 1_000_000).toString("latin1") +
        buf.subarray(buf.length - 500_000).toString("latin1")
      : buf.toString("latin1");
  const found: string[] = [];
  for (const { re, label } of EDITOR_SIGNATURES) {
    if (re.test(text) && !found.includes(label)) found.push(label);
  }
  if (text.includes("Photoshop 3.0") && !found.includes("Adobe Photoshop")) {
    found.push("Adobe Photoshop");
  }
  return found;
}

/**
 * Error Level Analysis (ELA-lite): re-encode as JPEG and compare pixel error map.
 * Edited / pasted / marked regions usually show higher residual error than pristine areas.
 */
async function analyzeErrorLevel(filePath: string): Promise<ForensicSignal | null> {
  try {
    const base = sharp(filePath, { failOn: "none" }).rotate().removeAlpha();
    const meta = await base.metadata();
    const width = meta.width ?? 0;
    const height = meta.height ?? 0;
    if (width < 32 || height < 32) return null;

    // Cap work for very large scans
    const maxSide = 1600;
    const scale =
      Math.max(width, height) > maxSide ? maxSide / Math.max(width, height) : 1;
    const w = Math.max(8, Math.round(width * scale));
    const h = Math.max(8, Math.round(height * scale));

    const { data: orig, info } = await base
      .clone()
      .resize(w, h, { fit: "fill" })
      .raw()
      .toBuffer({ resolveWithObject: true });

    const recompressedJpeg = await base
      .clone()
      .resize(w, h, { fit: "fill" })
      .jpeg({ quality: 90, mozjpeg: true })
      .toBuffer();

    const { data: recom } = await sharp(recompressedJpeg)
      .raw()
      .toBuffer({ resolveWithObject: true });

    const channels = info.channels || 3;
    const pixels = Math.floor(orig.length / channels);
    if (pixels < 64 || recom.length !== orig.length) return null;

    let sum = 0;
    let sumSq = 0;
    let hot = 0;
    const HOT_THRESHOLD = 28; // per-channel mean abs error

    for (let i = 0; i < pixels; i++) {
      const o = i * channels;
      let err = 0;
      for (let c = 0; c < Math.min(3, channels); c++) {
        const a = orig[o + c] ?? 0;
        const b = recom[o + c] ?? 0;
        err += Math.abs(a - b);
      }
      err /= Math.min(3, channels);
      sum += err;
      sumSq += err * err;
      if (err >= HOT_THRESHOLD) hot++;
    }

    const mean = sum / pixels;
    const variance = Math.max(0, sumSq / pixels - mean * mean);
    const std = Math.sqrt(variance);
    const hotRatio = hot / pixels;

    // Pristine camera/docs: low mean + low hot ratio.
    // Local edits (marks, whiteouts, pasted text) → elevated hotRatio / std.
    const suspicious =
      (hotRatio >= 0.045 && mean >= 6) ||
      (hotRatio >= 0.08 && std >= 8) ||
      (mean >= 14 && std >= 12);

    if (suspicious) {
      return {
        code: "IMAGE_ELA_ANOMALY",
        threatCode: "T051",
        severity: "high",
        score: 32,
        status: "failed",
        title: "Image edit residual anomaly (ELA)",
        description: `Error-level analysis found uneven compression residuals (hot ${(
          hotRatio * 100
        ).toFixed(1)}%, mean ${mean.toFixed(1)}) — typical of local edits, marks, or pasted regions.`,
        evidence: {
          meanError: Number(mean.toFixed(3)),
          stdError: Number(std.toFixed(3)),
          hotPixelRatio: Number(hotRatio.toFixed(4)),
          analyzedSize: `${w}x${h}`,
          format: meta.format ?? null,
        },
      };
    }

    return {
      code: "IMAGE_ELA_OK",
      threatCode: "T051",
      severity: "low",
      score: 0,
      status: "passed",
      title: "Image ELA consistent",
      description: `Error-level residuals look consistent (hot ${(hotRatio * 100).toFixed(
        1
      )}%, mean ${mean.toFixed(1)}).`,
      evidence: {
        meanError: Number(mean.toFixed(3)),
        stdError: Number(std.toFixed(3)),
        hotPixelRatio: Number(hotRatio.toFixed(4)),
        analyzedSize: `${w}x${h}`,
      },
    };
  } catch (err) {
    console.warn("[OCR:FORENSICS] ELA skipped:", (err as Error)?.message ?? err);
    return {
      code: "IMAGE_ELA_SKIPPED",
      threatCode: "T051",
      severity: "low",
      score: 0,
      status: "skipped",
      title: "Image ELA skipped",
      description: "Could not run error-level analysis on this file.",
    };
  }
}

async function analyzeExifSoftware(filePath: string): Promise<ForensicSignal | null> {
  try {
    const meta = await sharp(filePath, { failOn: "none" }).metadata();
    const blobs: Buffer[] = [];
    if (meta.exif) blobs.push(Buffer.from(Uint8Array.from(meta.exif as Uint8Array)));
    if (meta.xmp) blobs.push(Buffer.from(Uint8Array.from(meta.xmp as Uint8Array)));
    if (meta.iptc) blobs.push(Buffer.from(Uint8Array.from(meta.iptc as Uint8Array)));
    if (!blobs.length) return null;

    const text = blobs.map((b) => b.toString("latin1")).join("");
    const editors = EDITOR_SIGNATURES.filter(({ re }) => re.test(text)).map((e) => e.label);
    const unique = [...new Set(editors)];
    if (unique.length) {
      return {
        code: "IMAGE_EDITOR_METADATA",
        threatCode: "T052",
        severity: "high",
        score: 28,
        status: "failed",
        title: "Image editor metadata found",
        description: `EXIF/XMP references editing software: ${unique.join(", ")}.`,
        evidence: { editors: unique },
      };
    }
    return {
      code: "IMAGE_METADATA_RECORDED",
      threatCode: "T052",
      severity: "low",
      score: 0,
      status: "info",
      title: "Image metadata present",
      description: "EXIF/XMP present without known editor software tags.",
      evidence: {
        hasExif: Boolean(meta.exif),
        hasXmp: Boolean(meta.xmp),
        width: meta.width ?? null,
        height: meta.height ?? null,
      },
    };
  } catch {
    return null;
  }
}

/**
 * Image-category forensics: magic, size, editor signatures, EXIF, ELA.
 */
export async function analyzeImageForensics(
  filePath: string,
  originalFileName?: string,
  mimeTypeHint?: string
): Promise<ForensicSignal[]> {
  const buffer = fs.readFileSync(filePath);
  const ext =
    path.extname(originalFileName || "").replace(".", "").toLowerCase() ||
    path.extname(filePath).replace(".", "").toLowerCase() ||
    mimeToExt(mimeTypeHint);
  const magic = detectImageMagic(buffer);
  const signals: ForensicSignal[] = [];

  if (magic) {
    signals.push({
      code: "IMAGE_TYPE_RECORDED",
      threatCode: "T011",
      severity: "low",
      score: 0,
      status: "info",
      title: "Image type recorded",
      description: `Detected image type "${magic}" (extension ".${ext || "unknown"}").`,
      evidence: { magic, extension: ext, sizeBytes: buffer.length },
    });
  } else {
    signals.push({
      code: "IMAGE_TYPE_RECORDED",
      threatCode: "T011",
      severity: "low",
      score: 0,
      status: "info",
      title: "Image type recorded",
      description: `Could not classify image magic; extension ".${ext || "unknown"}".`,
      evidence: { extension: ext, sizeBytes: buffer.length },
    });
  }

  if (buffer.length > 0 && buffer.length < 512) {
    signals.push({
      code: "IMAGE_EMPTY_OR_TINY",
      threatCode: "T012",
      severity: "medium",
      score: 10,
      status: "failed",
      title: "Image file too small",
      description: `Image is only ${buffer.length} bytes — may be incomplete or placeholder.`,
      evidence: { sizeBytes: buffer.length },
    });
  }

  const embeddedEditors = findEditorSignatures(buffer);
  if (embeddedEditors.length) {
    signals.push({
      code: "IMAGE_EDITOR_SIGNATURE",
      threatCode: "T053",
      severity: "high",
      score: 30,
      status: "failed",
      title: "Image contains editor signatures",
      description: `Binary/metadata fingerprints of editing tools found: ${embeddedEditors.join(
        ", "
      )}.`,
      evidence: { editors: embeddedEditors },
    });
  } else {
    signals.push({
      code: "IMAGE_EDITOR_SIGNATURE_CLEAR",
      threatCode: "T053",
      severity: "low",
      score: 0,
      status: "passed",
      title: "No editor binary signatures",
      description: "No common photo-editor fingerprints found in the file bytes.",
    });
  }

  const exifSignal = await analyzeExifSoftware(filePath);
  if (exifSignal) signals.push(exifSignal);

  const ela = await analyzeErrorLevel(filePath);
  if (ela) signals.push(ela);

  const markOverlay = await analyzeInkMarkOverlay(filePath);
  if (markOverlay) signals.push(markOverlay);

  return signals;
}

/**
 * Detect pen / digital annotation overlays (circles, scribbles, highlighter)
 * that ELA often misses on already-compressed phone photos of KYC cards.
 * Looks for saturated ink-like colors atypical of clean Aadhaar/PAN scans
 * (especially blue/cyan markup circles).
 */
async function analyzeInkMarkOverlay(filePath: string): Promise<ForensicSignal | null> {
  try {
    const base = sharp(filePath, { failOn: "none" }).rotate().removeAlpha();
    const meta = await base.metadata();
    const width = meta.width ?? 0;
    const height = meta.height ?? 0;
    if (width < 48 || height < 48) return null;

    const maxSide = 1200;
    const scale =
      Math.max(width, height) > maxSide ? maxSide / Math.max(width, height) : 1;
    const w = Math.max(16, Math.round(width * scale));
    const h = Math.max(16, Math.round(height * scale));

    const { data, info } = await base
      .clone()
      .resize(w, h, { fit: "fill" })
      .raw()
      .toBuffer({ resolveWithObject: true });

    const channels = info.channels || 3;
    const pixels = Math.floor(data.length / channels);
    if (pixels < 256) return null;

    let ink = 0;
    let blueInk = 0;
    let redInk = 0;
    let yellowInk = 0;
    let magentaInk = 0;

    // Spatial grid to require clustered marks (not 1px noise)
    const cell = 16;
    const cols = Math.ceil(w / cell);
    const rows = Math.ceil(h / cell);
    const cellInk = new Uint16Array(cols * rows);

    for (let y = 0; y < h; y++) {
      for (let x = 0; x < w; x++) {
        const o = (y * w + x) * channels;
        const r = data[o] ?? 0;
        const g = data[o + 1] ?? 0;
        const b = data[o + 2] ?? 0;
        const kind = classifyInkPixel(r, g, b);
        if (!kind) continue;
        ink++;
        if (kind === "blue") blueInk++;
        else if (kind === "red") redInk++;
        else if (kind === "yellow") yellowInk++;
        else if (kind === "magenta") magentaInk++;
        const cx = Math.min(cols - 1, Math.floor(x / cell));
        const cy = Math.min(rows - 1, Math.floor(y / cell));
        cellInk[cy * cols + cx]++;
      }
    }

    let hotCells = 0;
    for (let i = 0; i < cellInk.length; i++) {
      if (cellInk[i] >= 12) hotCells++;
    }

    const inkRatio = ink / pixels;
    // Drawn circles on Aadhaar are typically a few hundred–thousand blue pixels
    // after downscale; require both volume and spatial clustering.
    const suspicious =
      (blueInk >= 350 && hotCells >= 2) ||
      (ink >= 500 && hotCells >= 3 && inkRatio >= 0.0008) ||
      (inkRatio >= 0.003 && hotCells >= 2) ||
      (blueInk >= 180 && hotCells >= 4);

    if (suspicious) {
      const dominant =
        blueInk >= redInk && blueInk >= yellowInk && blueInk >= magentaInk
          ? "blue_or_cyan_pen"
          : redInk >= yellowInk && redInk >= magentaInk
            ? "red_pen"
            : yellowInk >= magentaInk
              ? "yellow_highlighter"
              : "magenta_markup";

      return {
        code: "IMAGE_MARK_OVERLAY",
        threatCode: "T054",
        severity: "high",
        score: 38,
        status: "failed",
        title: "Pen / annotation marks detected on image",
        description: `Saturated ink-like overlay pixels found (${dominant}; ~${ink} px, ${hotCells} clusters) — typical of drawn circles, scribbles, or highlighter on a KYC document.`,
        evidence: {
          inkPixels: ink,
          blueInk,
          redInk,
          yellowInk,
          magentaInk,
          inkRatio: Number(inkRatio.toFixed(5)),
          hotCells,
          dominant,
          analyzedSize: `${w}x${h}`,
        },
      };
    }

    return {
      code: "IMAGE_MARK_OVERLAY_CLEAR",
      threatCode: "T054",
      severity: "low",
      score: 0,
      status: "passed",
      title: "No pen/annotation overlay detected",
      description: `No clustered ink-like overlay colors found (ink px ${ink}, clusters ${hotCells}).`,
      evidence: {
        inkPixels: ink,
        blueInk,
        hotCells,
        inkRatio: Number(inkRatio.toFixed(5)),
        analyzedSize: `${w}x${h}`,
      },
    };
  } catch (err) {
    console.warn(
      "[OCR:FORENSICS] Mark-overlay analysis skipped:",
      (err as Error)?.message ?? err
    );
    return {
      code: "IMAGE_MARK_OVERLAY_SKIPPED",
      threatCode: "T054",
      severity: "low",
      score: 0,
      status: "skipped",
      title: "Mark-overlay analysis skipped",
      description: "Could not scan image for pen/annotation overlays.",
    };
  }
}

/** Classify saturated ink colors while avoiding Aadhaar saffron/green header bands. */
function classifyInkPixel(
  r: number,
  g: number,
  b: number
): "blue" | "red" | "yellow" | "magenta" | null {
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  if (max < 40) return null;
  const sat = (max - min) / max;
  if (sat < 0.32) return null;

  // Skip muted header greens (Aadhaar band) — need vivid highlighter green/yellow
  // Skip saffron/orange emblem (high R, mid G, low B) unless very pure red pen

  // Blue / cyan digital or ballpoint annotation (the common “circle the name” case)
  if (b >= 85 && b >= r + 28 && b >= g + 18 && b >= max * 0.88 && sat >= 0.34) {
    return "blue";
  }

  // Magenta / purple markup
  if (
    r >= 90 &&
    b >= 90 &&
    g <= Math.min(r, b) - 25 &&
    sat >= 0.36 &&
    Math.min(r, b) >= max * 0.75
  ) {
    return "magenta";
  }

  // Yellow highlighter (bright Y, not orange saffron)
  if (r >= 170 && g >= 160 && b <= 110 && sat >= 0.38 && g >= r * 0.75) {
    return "yellow";
  }

  // Pure-ish red pen (not saffron: saffron has higher green)
  if (r >= 160 && g <= 70 && b <= 70 && sat >= 0.48 && r >= max * 0.9) {
    return "red";
  }

  return null;
}

function mimeToExt(mimeTypeHint?: string): string {
  const mime = (mimeTypeHint || "").toLowerCase();
  if (mime.includes("jpeg") || mime.includes("jpg")) return "jpg";
  if (mime.includes("png")) return "png";
  if (mime.includes("webp")) return "webp";
  if (mime.includes("gif")) return "gif";
  if (mime.includes("bmp")) return "bmp";
  if (mime.includes("tiff")) return "tiff";
  return "";
}

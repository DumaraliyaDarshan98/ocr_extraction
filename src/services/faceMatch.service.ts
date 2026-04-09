import path from "path";
import { loadImage } from "canvas";
import { getKycThresholds, isFaceMatchEnabled } from "../config/kyc.config";

let modelsLoaded = false;
let faceApiModule: any | null = null;

async function getFaceApi(): Promise<any> {
  if (faceApiModule) {
    return faceApiModule;
  }
  // Lazy import so missing tfjs-node does not crash server startup.
  faceApiModule = await import("@vladmandic/face-api");
  return faceApiModule;
}

function resolveModelDir(): string {
  return path.join(
    path.dirname(require.resolve("@vladmandic/face-api/package.json")),
    "model"
  );
}

async function ensureModels(): Promise<void> {
  if (modelsLoaded) {
    return;
  }
  const faceapi = await getFaceApi();
  const dir = resolveModelDir();
  await faceapi.nets.ssdMobilenetv1.loadFromDisk(dir);
  await faceapi.nets.faceLandmark68Net.loadFromDisk(dir);
  await faceapi.nets.faceRecognitionNet.loadFromDisk(dir);
  modelsLoaded = true;
}

async function getDescriptor(imagePath: string): Promise<Float32Array> {
  const faceapi = await getFaceApi();
  const img = await loadImage(imagePath);
  const detection = await faceapi
    .detectSingleFace(img as unknown)
    .withFaceLandmarks()
    .withFaceDescriptor();
  if (!detection) {
    throw new Error("No face detected in image");
  }
  return detection.descriptor;
}

/**
 * Maps Euclidean distance to a 0–1 similarity score (higher = more similar).
 */
function distanceToScore(distance: number): number {
  const { faceDistanceMax } = getKycThresholds();
  const max = faceDistanceMax > 0 ? faceDistanceMax : 0.55;
  return Math.max(0, Math.min(1, 1 - distance / max));
}

/**
 * Compares faces in two image files. Returns null if face matching is disabled or models fail.
 */
export async function compareFaceImages(
  documentImagePath: string,
  selfieImagePath: string
): Promise<{ score: number; error?: string } | null> {
  if (!isFaceMatchEnabled()) {
    return null;
  }

  try {
    const faceapi = await getFaceApi();
    await ensureModels();
    const [d1, d2] = await Promise.all([
      getDescriptor(documentImagePath),
      getDescriptor(selfieImagePath),
    ]);
    const distance = faceapi.euclideanDistance(d1, d2);
    const score = distanceToScore(distance);
    return { score };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { score: 0, error: msg };
  }
}

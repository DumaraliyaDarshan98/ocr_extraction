import fs from "fs";
import path from "path";
import type { TriggerConfigFile } from "../validation/types";

let cache: TriggerConfigFile | null = null;
let cachePath: string | null = null;

function resolveConfigPath(): string {
  const envPath = process.env.TRIGGER_CONFIG_PATH;
  if (envPath && envPath.length > 0) {
    return path.isAbsolute(envPath)
      ? envPath
      : path.join(process.cwd(), envPath);
  }
  return path.join(__dirname, "..", "config", "triggers");
}

function isTriggerConfigFile(x: unknown): x is TriggerConfigFile {
  const v = x as TriggerConfigFile;
  return !!v && typeof v.version === "number" && Array.isArray(v.triggers);
}

function readTriggerFile(filePath: string): TriggerConfigFile {
  const raw = fs.readFileSync(filePath, "utf-8");
  const parsed = JSON.parse(raw) as unknown;
  if (!isTriggerConfigFile(parsed)) {
    throw new Error(`Invalid trigger config at ${filePath}`);
  }
  return parsed;
}

function loadFromDirectory(dirPath: string): TriggerConfigFile {
  const files = fs
    .readdirSync(dirPath)
    .filter((f) => f.toLowerCase().endsWith(".json"))
    .sort();

  const merged: TriggerConfigFile = { version: 1, triggers: [] };
  for (const file of files) {
    const full = path.join(dirPath, file);
    const cfg = readTriggerFile(full);
    merged.version = Math.max(merged.version, cfg.version);
    merged.triggers.push(...cfg.triggers);
  }
  return merged;
}

/**
 * Loads trigger JSON (from Excel export or hand-written file).
 * Cached until process restart or invalidateTriggerConfigCache().
 */
export function loadTriggerConfig(): TriggerConfigFile {
  const p = resolveConfigPath();
  if (cache && cachePath === p) {
    return cache;
  }

  const stat = fs.existsSync(p) ? fs.statSync(p) : null;
  if (!stat) {
    throw new Error(`Trigger config path not found: ${p}`);
  }

  cache = stat.isDirectory() ? loadFromDirectory(p) : readTriggerFile(p);
  cachePath = p;
  return cache;
}

export function invalidateTriggerConfigCache(): void {
  cache = null;
  cachePath = null;
}

export function hasTriggersForDocumentType(
  documentType: string,
  config: TriggerConfigFile
): boolean {
  const t = documentType.trim().toLowerCase();
  return config.triggers.some(
    (r) => r.documentType.trim().toLowerCase() === t
  );
}

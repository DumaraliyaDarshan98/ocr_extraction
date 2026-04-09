/**
 * Usage: npx ts-node src/scripts/importTriggersFromExcel.ts <input.xlsx> [output.json]
 * Default output: src/config/validation-triggers.json (relative to cwd)
 */
import fs from "fs";
import path from "path";
import { excelBufferToTriggerConfig } from "../utils/excelToTriggers";

function main(): void {
  const input = process.argv[2];
  const outArg = process.argv[3];
  if (!input) {
    console.error(
      "Usage: npx ts-node src/scripts/importTriggersFromExcel.ts <input.xlsx> [output.json]"
    );
    process.exit(1);
  }

  const abs = path.isAbsolute(input) ? input : path.join(process.cwd(), input);
  const buffer = fs.readFileSync(abs);
  const config = excelBufferToTriggerConfig(buffer, 1);
  const outPath =
    outArg !== undefined
      ? path.isAbsolute(outArg)
        ? outArg
        : path.join(process.cwd(), outArg)
      : path.join(process.cwd(), "src", "config", "validation-triggers.json");

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, `${JSON.stringify(config, null, 2)}\n`, "utf-8");
  console.log(`Wrote ${config.triggers.length} triggers to ${outPath}`);
}

main();

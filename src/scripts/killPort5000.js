/* eslint-disable no-console */
const { execSync } = require("child_process");

function getPidsFromNetstat(port) {
  const output = execSync(`netstat -ano -p tcp`, { encoding: "utf8" });
  const lines = output.split(/\r?\n/);
  const pids = new Set();

  for (const line of lines) {
    // Example:
    // TCP    0.0.0.0:5000           0.0.0.0:0              LISTENING       14440
    if (!line.includes(`:${port}`)) continue;
    if (!line.includes("LISTENING")) continue;
    const parts = line.trim().split(/\s+/);
    const pid = parts[parts.length - 1];
    if (pid && /^\d+$/.test(pid)) {
      pids.add(pid);
    }
  }

  return Array.from(pids);
}

function killPid(pid) {
  try {
    execSync(`taskkill /PID ${pid} /F`, { stdio: "ignore" });
    console.log(`[predev] Killed process PID ${pid} on port 5000`);
  } catch {
    // ignore
  }
}

function main() {
  const port = 5000;
  const pids = getPidsFromNetstat(port);
  for (const pid of pids) {
    killPid(pid);
  }
}

main();


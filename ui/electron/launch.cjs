#!/usr/bin/env node
const { spawn } = require("node:child_process");

const electron = require("electron");

const env = { ...process.env };
if (process.platform === "linux" && env.EMBER_USE_PORTAL_FILE_PICKER !== "1") {
  env.GTK_USE_PORTAL ??= "0";
  env.GIO_USE_PORTALS ??= "0";
  env.GDK_DEBUG ??= "no-portals";
}

const child = spawn(electron, process.argv.slice(2), {
  env,
  stdio: ["inherit", "inherit", "pipe"],
});

let forwardingSignal = null;
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.once(sig, () => {
    forwardingSignal = sig;
    if (!child.killed) child.kill(sig);
    setTimeout(() => {
      if (!child.killed) child.kill("SIGKILL");
    }, 1500).unref();
  });
}

let pending = "";
function isNoisyPortalLine(line) {
  return line.includes("Failed to read portal settings") ||
         line.includes("select_file_dialog_linux_portal.cc");
}

child.stderr.on("data", (chunk) => {
  pending += chunk.toString();
  const lines = pending.split(/\r?\n/);
  pending = lines.pop() ?? "";
  for (const line of lines) {
    if (isNoisyPortalLine(line)) continue;
    process.stderr.write(line + "\n");
  }
});

child.on("close", (code, signal) => {
  if (pending && !isNoisyPortalLine(pending)) {
    process.stderr.write(pending);
  }
  if (forwardingSignal) process.exit(128 + (forwardingSignal === "SIGINT" ? 2 : 15));
  if (signal) process.exit(128 + (signal === "SIGINT" ? 2 : 15));
  process.exit(code ?? 0);
});

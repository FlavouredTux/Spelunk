#!/usr/bin/env node
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const electron = require("electron");

function isElectronAppArg(arg) {
  if (!arg || arg.startsWith("-")) return false;
  if (/^https?:\/\//i.test(arg) || /^file:\/\//i.test(arg)) return true;
  const p = path.resolve(process.cwd(), arg);
  try {
    const st = fs.statSync(p);
    if (st.isDirectory()) return fs.existsSync(path.join(p, "package.json")) ||
                           fs.existsSync(path.join(p, "index.js"));
    if (st.isFile()) return /\.(js|cjs|mjs|html?|json)$/i.test(p);
  } catch {
    return false;
  }
  return false;
}

const userArgs = process.argv.slice(2);
const appRoot = path.resolve(__dirname, "..");
const explicitAppArg = isElectronAppArg(userArgs[0]);
const electronArgs = explicitAppArg ? userArgs : [appRoot, ...userArgs];

const env = { ...process.env };
if (explicitAppArg) {
  env.VITE_DEV_SERVER_URL ??= "http://localhost:5173";
}
if (process.platform === "linux" && env.EMBER_USE_PORTAL_FILE_PICKER !== "1") {
  env.GTK_USE_PORTAL ??= "0";
  env.GIO_USE_PORTALS ??= "0";
  env.GDK_DEBUG ??= "no-portals";
}

const child = spawn(electron, electronArgs, {
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

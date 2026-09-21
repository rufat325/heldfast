#!/usr/bin/env node
"use strict";

/**
 * npx @rufat325/mcp-pin -- <server>
 *
 * The npm name `mcp-pin` belongs to GautamTalksDev/mcp-pin (TOFU on first
 * connect). This shim is the wrap for rufat325/mcp-pin: it locates a Python
 * install of that tool and execs it. It does not download a wheel on its
 * own — a supply-chain pin that fetches Python from the network at spawn
 * would be asking you to trust the thing it is pinning.
 */

const { spawn } = require("child_process");
const { spawnSync } = require("child_process");

function canRun(cmd, args) {
  const r = spawnSync(cmd, args, { encoding: "utf8", timeout: 8000 });
  return r.status === 0;
}

function findRunner() {
  if (canRun("mcp-pin", ["--version"])) {
    return { cmd: "mcp-pin", prefix: [] };
  }
  for (const py of ["python3", "python"]) {
    if (canRun(py, ["-c", "import mcp_pin"])) {
      return { cmd: py, prefix: ["-m", "mcp_pin"] };
    }
  }
  return null;
}

function main(argv) {
  let rest = argv.slice(2);
  if (rest[0] === "--") {
    rest = ["wrap", ...rest];
  }
  const runner = findRunner();
  if (!runner) {
    process.stderr.write(
      "mcp-pin: the Python package is not installed.\n" +
        "         pipx install mcp-pin\n" +
        "         (npx mcp-pin is a different project: GautamTalksDev/mcp-pin)\n"
    );
    process.exit(2);
  }
  const child = spawn(runner.cmd, [...runner.prefix, ...rest], {
    stdio: "inherit",
    windowsHide: true,
  });
  child.on("exit", (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    process.exit(code == null ? 1 : code);
  });
}

main(process.argv);

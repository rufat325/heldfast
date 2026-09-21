#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { toolDigest, checkLock, findLock } = require("./index.js");

function die(msg, code) {
  process.stderr.write("mcp-pin-check: " + msg + "\n");
  process.exit(code);
}

function main(argv) {
  const args = argv.slice(2);
  if (args.includes("-h") || args.includes("--help")) {
    process.stdout.write(
      "mcp-pin-check — verify .mcp-pin.lock (zero dependencies)\n\n" +
        "  mcp-pin-check                 check ./.mcp-pin.lock\n" +
        "  mcp-pin-check --lock PATH     check a specific file\n" +
        "  mcp-pin-check --tool FILE     print the digest of one tool object\n" +
        "  mcp-pin-check --golden DIR    verify golden vectors (same object, same digest)\n"
    );
    return 0;
  }

  let lockArg = null;
  let toolArg = null;
  let goldenArg = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--lock") lockArg = args[++i];
    else if (args[i] === "--tool") toolArg = args[++i];
    else if (args[i] === "--golden") goldenArg = args[++i];
    else if (args[i] === "--version") {
      process.stdout.write("mcp-pin-check 0.1.4\n");
      return 0;
    } else die("unknown argument " + args[i], 2);
  }

  if (toolArg) {
    const tool = JSON.parse(fs.readFileSync(toolArg, "utf8"));
    const obj = tool.tool || tool;
    process.stdout.write(toolDigest(obj) + "\n");
    return 0;
  }

  if (goldenArg) {
    const dir = goldenArg;
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
    if (!files.length) die("no golden files in " + dir, 2);
    let failed = 0;
    for (const name of files) {
      const rec = JSON.parse(fs.readFileSync(path.join(dir, name), "utf8"));
      const got = toolDigest(rec.tool);
      if (got !== rec.digest) {
        process.stderr.write(name + " expected " + rec.digest + " got " + got + "\n");
        failed++;
      }
    }
    if (failed) die(failed + " golden vector(s) disagreed", 1);
    process.stdout.write("mcp-pin-check: " + files.length + " golden vector(s) ok\n");
    return 0;
  }

  const lockPath = lockArg || findLock(process.cwd());
  const result = checkLock(lockPath);
  if (!result.ok) {
    die((result.code ? result.code + "  " : "") + result.message, result.code === "MCPA014" ? 1 : 2);
  }
  process.stdout.write(
    "mcp-pin-check: " + result.path + " ok  version " + result.version +
      "  " + result.servers + " server(s)  " + result.tools + " tool(s)\n"
  );
  return 0;
}

process.exit(main(process.argv));

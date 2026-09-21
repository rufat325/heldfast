"use strict";

/**
 * Canonical MCP tool digest. Must match src/mcp_pin/digest.py:
 * JSON (sorted keys, no whitespace, Unicode kept) -> UTF-8 -> SHA-256 hex.
 *
 * Zero runtime dependencies. Node 18+ (global crypto.webcrypto / crypto.hash).
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

function canonical(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("non-finite numbers are not in the digest");
    }
    // Python json.dumps emits 1 for ints and 1.0 for floats. Goldens use
    // integers; a float must keep a decimal so the two sides can agree.
    return Number.isInteger(value) ? String(value) : JSON.stringify(value);
  }
  if (t === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonical).join(",") + "]";
  }
  if (t === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
  }
  throw new TypeError("unsupported digest value: " + t);
}

function mapping(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function toolBody(tool) {
  const schema = tool.input_schema !== undefined ? tool.input_schema : tool.inputSchema;
  const annotations = tool.annotations;
  const body = {
    name: tool.name == null ? "" : String(tool.name),
    title: tool.title == null ? "" : String(tool.title),
    description: tool.description == null ? "" : String(tool.description),
    input_schema: mapping(schema),
    annotations: mapping(annotations),
  };
  let output = tool.output_schema;
  if (output === undefined) output = tool.outputSchema;
  if (output && typeof output === "object" && !Array.isArray(output) && Object.keys(output).length) {
    body.output_schema = output;
  }
  const icons = tool.icons;
  if (Array.isArray(icons) && icons.length) body.icons = icons;
  return body;
}

function toolDigest(tool) {
  const payload = canonical(toolBody(tool));
  return crypto.createHash("sha256").update(payload, "utf8").digest("hex");
}

function loadLock(lockPath) {
  const raw = fs.readFileSync(lockPath, "utf8");
  const data = JSON.parse(raw);
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new Error(lockPath + ": lockfile is not an object");
  }
  return data;
}

const LOCK_VERSION = 1;

function checkLock(lockPath) {
  if (!fs.existsSync(lockPath)) {
    return { ok: false, code: "MCPA014", message: "no lockfile at " + lockPath };
  }
  let data;
  try {
    data = loadLock(lockPath);
  } catch (err) {
    return { ok: false, code: "ERROR", message: String(err.message || err) };
  }
  const version = Number(data.version || 0);
  if (version > LOCK_VERSION) {
    return {
      ok: false,
      code: "T-LOCK-FUTURE",
      message: lockPath + ": lockfile version " + version + " is newer than this checker understands",
    };
  }
  const servers = data.servers && typeof data.servers === "object" ? data.servers : {};
  let tools = 0;
  for (const entry of Object.values(servers)) {
    if (entry && typeof entry === "object" && entry.tools && typeof entry.tools === "object") {
      tools += Object.keys(entry.tools).length;
    }
  }
  return {
    ok: true,
    path: lockPath,
    version: version || LOCK_VERSION,
    servers: Object.keys(servers).length,
    tools,
  };
}

function findLock(cwd) {
  const current = path.join(cwd, ".mcp-pin.lock");
  if (fs.existsSync(current)) return current;
  const legacy = path.join(cwd, ".mcp-audit.lock");
  if (fs.existsSync(legacy)) return legacy;
  return current;
}

module.exports = {
  LOCK_VERSION,
  canonical,
  toolBody,
  toolDigest,
  loadLock,
  checkLock,
  findLock,
};

"use strict";

/**
 * Tiny lock reader for Claude Code hooks. Stdlib only.
 * Digest matches js/mcp-pin-check and src/mcp_pin/digest.py.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

function canonical(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-finite numbers");
    return Number.isInteger(value) ? String(value) : JSON.stringify(value);
  }
  if (t === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (t === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
  }
  throw new TypeError("unsupported " + t);
}

function mapping(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function toolBody(tool) {
  const schema = tool.input_schema !== undefined ? tool.input_schema : tool.inputSchema;
  const body = {
    name: tool.name == null ? "" : String(tool.name),
    title: tool.title == null ? "" : String(tool.title),
    description: tool.description == null ? "" : String(tool.description),
    input_schema: mapping(schema),
    annotations: mapping(tool.annotations),
  };
  let output = tool.output_schema;
  if (output === undefined) output = tool.outputSchema;
  if (output && typeof output === "object" && !Array.isArray(output) && Object.keys(output).length) {
    body.output_schema = output;
  }
  if (Array.isArray(tool.icons) && tool.icons.length) body.icons = tool.icons;
  return body;
}

function toolDigest(tool) {
  return crypto.createHash("sha256").update(canonical(toolBody(tool)), "utf8").digest("hex");
}

function findLock(cwd) {
  const current = path.join(cwd, ".mcp-pin.lock");
  if (fs.existsSync(current)) return current;
  const legacy = path.join(cwd, ".mcp-audit.lock");
  if (fs.existsSync(legacy)) return legacy;
  return null;
}

function loadLock(cwd) {
  const lockPath = findLock(cwd);
  if (!lockPath) return { path: null, data: null };
  const data = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  return { path: lockPath, data };
}

function findServerEntry(lock, serverName) {
  if (!lock || !lock.servers || typeof lock.servers !== "object") return null;
  const servers = lock.servers;
  if (servers[serverName] && typeof servers[serverName] === "object") {
    return servers[serverName];
  }
  const suffix = ":" + serverName;
  const matches = Object.keys(servers).filter((k) => k === serverName || k.endsWith(suffix));
  if (matches.length === 1) return servers[matches[0]];
  for (const key of Object.keys(servers)) {
    const entry = servers[key];
    if (entry && entry.name === serverName) return entry;
  }
  return null;
}

function parseMcpTool(name) {
  const m = /^mcp__(.+)__(.+)$/.exec(name || "");
  if (!m) return null;
  return { server: m[1], tool: m[2] };
}

function readStdin() {
  return new Promise((resolve) => {
    let buf = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => { buf += c; });
    process.stdin.on("end", () => resolve(buf));
  });
}

module.exports = {
  toolDigest,
  findLock,
  loadLock,
  findServerEntry,
  parseMcpTool,
  readStdin,
};

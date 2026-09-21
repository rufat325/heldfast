"use strict";

/**
 * Tiny lock reader for Claude Code hooks. Stdlib only.
 *
 * RFC 8785 (JCS). Must match js/mcp-pin-check/index.js and
 * src/mcp_pin/digest.py byte for byte. This is the third copy of the
 * algorithm and the one that decides whether a PreToolUse hook denies a
 * call, so a disagreement here shows up as the tool refusing work the user
 * approved -- which is exactly what `1.0` used to do, on every Pydantic or
 * FastMCP server that writes a `"minimum": 0.0` bound.
 *
 * It cannot `require` the checker: the plugin is distributed on its own.
 * `tests/test_digest_parity.py` hashes the shared golden vectors through
 * this file and compares them against Python, so the copies cannot drift.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ESCAPES = {
  '"': '\\"',
  "\\": "\\\\",
  "\b": "\\b",
  "\f": "\\f",
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
};

// Lone surrogates are escaped rather than emitted raw: Node's JSON.stringify
// passes them through, and those are bytes Python's UTF-8 encoder refuses.
function escapeString(text) {
  let out = '"';
  for (const char of text) {
    const code = char.codePointAt(0);
    const escape = ESCAPES[char];
    if (escape !== undefined) out += escape;
    else if (code < 0x20 || (code >= 0xd800 && code <= 0xdfff)) {
      out += "\\u" + code.toString(16).padStart(4, "0");
    } else out += char;
  }
  return out + '"';
}

function canonical(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-finite numbers");
    // String(-0) is "0", the fold JCS specifies. Everything else is
    // ECMAScript Number::toString, which is what JCS defers to.
    return value === 0 ? "0" : String(value);
  }
  if (t === "string") return escapeString(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (t === "object") {
    // Array.prototype.sort on strings is already UTF-16 code-unit order,
    // which is what RFC 8785 section 3.2.3 requires.
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => escapeString(k) + ":" + canonical(value[k])).join(",") + "}";
  }
  throw new TypeError("unsupported " + t);
}

function mapping(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function toolBody(tool) {
  // `== null` is deliberate: it covers `null` as well as `undefined`. Python's
  // tool_body falls back on `is None`, so a tool carrying BOTH spellings with
  // the snake_case one explicitly null -- which a server chooses -- hashed one
  // way here and another way there. That is the one thing this algorithm
  // exists to prevent: the Python guard and this copy would answer differently
  // about the same frame. Golden vectors 13 and 14 hold the line.
  const schema = tool.input_schema != null ? tool.input_schema : tool.inputSchema;
  const body = {
    name: tool.name == null ? "" : String(tool.name),
    title: tool.title == null ? "" : String(tool.title),
    description: tool.description == null ? "" : String(tool.description),
    input_schema: mapping(schema),
    annotations: mapping(tool.annotations),
  };
  let output = tool.output_schema;
  if (output == null) output = tool.outputSchema;
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
  canonical,
  toolDigest,
  findLock,
  loadLock,
  findServerEntry,
  parseMcpTool,
  readStdin,
};

"use strict";

/**
 * Tiny lock reader for Claude Code hooks. Stdlib only.
 *
 * RFC 8785 (JCS). Must match js/heldfast-check/index.js and
 * src/heldfast/digest.py byte for byte. This is the third copy of the
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
const os = require("os");
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

// Lockfile versions this hook understands, kept in step with index.js and
// lockfile.py. A file from the future is refused rather than read with
// today's meaning; a version 1 file holds pre-JCS digests that cannot be
// compared with the ones computed now.
const LOCK_VERSION = 2;
const DIGEST_CHANGED_IN = 2;

/**
 * Resolve a bare server name to exactly one lock entry.
 *
 * Returns {entry} when one matched, {ambiguous: n} when several did, or null
 * when none did. The count matters: entries are keyed `client:name` because
 * two clients can each configure a server called `github` and they are not
 * the same server. Taking the first match meant Cursor's approvals governed
 * Claude Code's server -- allowing a tool that was approved somewhere else,
 * which is the whole failure T-DRIFT-ID names. `guard.py` refuses to guess
 * here and so does this.
 */
function findServerEntry(lock, serverName) {
  if (!lock || !lock.servers || typeof lock.servers !== "object") return null;
  const servers = lock.servers;
  // An explicit `client:name` wins outright, the same as --name does.
  if (servers[serverName] && typeof servers[serverName] === "object") {
    return { entry: servers[serverName] };
  }
  const suffix = ":" + serverName;
  const matches = Object.keys(servers).filter((key) => {
    const entry = servers[key];
    if (!entry || typeof entry !== "object") return false;
    return key === serverName || key.endsWith(suffix) || entry.name === serverName;
  });
  if (matches.length === 1) return { entry: servers[matches[0]] };
  if (matches.length > 1) return { ambiguous: matches.length };
  return null;
}

/**
 * How Claude Code writes a server's name inside a tool name: every character
 * outside [A-Za-z0-9_-] becomes "_", and a "claude.ai " server's runs of "_"
 * collapse and its edges are trimmed. Read from Claude Code 2.1.7's own
 * normaliser. A plugin's server is registered as `plugin:<plugin>:<server>`,
 * which this turns into `plugin_<plugin>_<server>`.
 */
function toolServerName(name) {
  let out = String(name).replace(/[^a-zA-Z0-9_-]/g, "_");
  if (String(name).startsWith("claude.ai ")) out = out.replace(/_+/g, "_").replace(/^_|_$/g, "");
  return out;
}

/**
 * The server and tool in `mcp__<server>__<tool>`, split the way Claude Code
 * splits it: at the first "__" after the prefix. Only good for naming things
 * in a message -- a server or a tool whose name holds "__" is split wrongly --
 * so a decision goes through resolveMcpTool instead.
 */
function parseMcpTool(name) {
  const parts = String(name || "").split("__");
  if (parts[0] !== "mcp" || parts.length < 3 || !parts[1]) return null;
  return { server: parts[1], tool: parts.slice(2).join("__") };
}

/**
 * Split a tool name against the servers the lock names, not a pattern.
 *
 * A greedy /^mcp__(.+)__(.+)$/ read `mcp__files__read__raw` as server
 * `files__read`, tool `raw`: the wrong server, the wrong tool. Here every
 * lock server is written the way Claude Code writes it; the longest one the
 * tool name starts with (as `mcp__<server>__`) is the server and the rest is
 * the tool. Returns {server, tool} with the lock's own spelling of the
 * server, {ambiguous: [...]} when two different servers fit equally well, or
 * null when none does.
 */
function resolveMcpTool(toolName, lock) {
  const servers = lock && lock.servers && typeof lock.servers === "object" ? lock.servers : {};
  const byWritten = new Map();
  for (const key of Object.keys(servers)) {
    const entry = servers[key];
    if (!entry || typeof entry !== "object") continue;
    const bare = typeof entry.name === "string" && entry.name ? entry.name
      : key.slice(key.indexOf(":") + 1);
    // A plugin's server is recorded as `<plugin>:<server>` and registered by
    // Claude Code as `plugin:<plugin>:<server>`.
    const fromPlugin = entry.client === "claude-code-plugin" || key.startsWith("claude-code-plugin:");
    const written = toolServerName(fromPlugin ? "plugin:" + bare : bare);
    if (!byWritten.has(written)) byWritten.set(written, new Set());
    byWritten.get(written).add(bare);
  }
  let best = null;
  for (const [written, bares] of byWritten) {
    const prefix = "mcp__" + written + "__";
    if (!String(toolName).startsWith(prefix) || String(toolName).length === prefix.length) continue;
    if (!best || written.length > best.written.length) best = { written, bares };
  }
  if (!best) return null;
  if (best.bares.size > 1) return { ambiguous: [...best.bares].sort() };
  return { server: [...best.bares][0], tool: String(toolName).slice(("mcp__" + best.written + "__").length) };
}

/**
 * Where a session's hosted-server check is kept: the plugin's data directory
 * when Claude Code gives one, else the temporary directory. One file per
 * session id, so one session's reading never governs another's.
 */
function sessionStatePath(sessionId) {
  if (!sessionId || typeof sessionId !== "string") return null;
  const dir = process.env.CLAUDE_PLUGIN_DATA || path.join(os.tmpdir(), "heldfast-plugin");
  return path.join(dir, "session-" + sessionId.replace(/[^A-Za-z0-9_-]/g, "-") + ".json");
}

function writeSessionState(sessionId, state) {
  const file = sessionStatePath(sessionId);
  if (!file) return;
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(state));
  } catch (_err) { /* no state: the session is checked by name only */ }
}

function readSessionState(sessionId) {
  const file = sessionStatePath(sessionId);
  if (!file || !fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, "utf8"));
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
  LOCK_VERSION,
  DIGEST_CHANGED_IN,
  canonical,
  toolDigest,
  findLock,
  loadLock,
  findServerEntry,
  parseMcpTool,
  resolveMcpTool,
  toolServerName,
  sessionStatePath,
  writeSessionState,
  readSessionState,
  readStdin,
};

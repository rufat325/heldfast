"use strict";

/**
 * Canonical MCP tool digest. Must match src/heldfast/digest.py:
 * RFC 8785 (JSON Canonicalization Scheme) -> UTF-8 -> SHA-256 hex.
 *
 * This file and digest.py are checked against the same golden vectors in
 * tests/golden/jcs_vectors.json, from both languages, because the previous
 * pair of hand-matched implementations disagreed on five ordinary inputs --
 * `1.0`, `1e16`, integers that lose precision as doubles, `-0.0`, and keys
 * mixing BMP with astral characters. JCS is what makes "same object, same
 * digest, any language" a specification rather than a hope.
 *
 * Zero runtime dependencies. Node 18+ (global crypto.webcrypto / crypto.hash).
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const ESCAPES = {
  '"': '\\"',
  "\\": "\\\\",
  "\b": "\\b",
  "\f": "\\f",
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
};

/**
 * A JSON string literal, escaped as JSON.stringify escapes -- except that a
 * lone surrogate becomes an explicit \udXXX escape instead of being emitted
 * raw. Node's JSON.stringify passes lone surrogates through since the
 * well-formed-stringify proposal, which would produce bytes Python's UTF-8
 * encoder refuses; spelling the escape out keeps both sides on ASCII.
 */
function escapeString(text) {
  let out = '"';
  for (const char of text) {
    const code = char.codePointAt(0);
    const escape = ESCAPES[char];
    if (escape !== undefined) {
      out += escape;
    } else if (code < 0x20 || (code >= 0xd800 && code <= 0xdfff)) {
      out += "\\u" + code.toString(16).padStart(4, "0");
    } else {
      out += char;
    }
  }
  return out + '"';
}

/**
 * Key order is by UTF-16 code unit, which is what RFC 8785 section 3.2.3
 * says and what a plain `Array.prototype.sort` on strings already does.
 * Python has to encode to UTF-16 to reach the same order; here it is free.
 */
function canonical(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("NaN and Infinity are not JSON numbers");
    }
    // No magnitude check here, deliberately. By this point JSON.parse has
    // already collapsed the source text to a double, so a literal that lost
    // precision is indistinguishable from one that did not -- 1e16 is above
    // 2**53 and exact, 9007199254740993 is above it and is not. Python can
    // still see the difference, because its ints are arbitrary precision, so
    // that refusal lives in digest.py at approve time. Here, JCS is simply
    // ECMAScript Number::toString, with String(-0) folded to "0".
    return value === 0 ? "0" : String(value);
  }
  if (t === "string") return escapeString(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonical).join(",") + "]";
  }
  if (t === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => escapeString(k) + ":" + canonical(value[k])).join(",") + "}";
  }
  throw new TypeError("unsupported digest value: " + t);
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
  const annotations = tool.annotations;
  const body = {
    name: tool.name == null ? "" : String(tool.name),
    title: tool.title == null ? "" : String(tool.title),
    description: tool.description == null ? "" : String(tool.description),
    input_schema: mapping(schema),
    annotations: mapping(annotations),
  };
  let output = tool.output_schema;
  if (output == null) output = tool.outputSchema;
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

// 2 changed the digest algorithm to RFC 8785 (JCS). A version 1 lock holds
// fingerprints this checker cannot reproduce, so it is reported as needing
// re-approval rather than as a wall of drift.
const LOCK_VERSION = 2;
const DIGEST_CHANGED_IN = 2;

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
  if (version && version < DIGEST_CHANGED_IN) {
    return {
      ok: false,
      code: "T-LOCK-STALE-DIGEST",
      message: lockPath + ": lockfile version " + version + " predates the RFC 8785 " +
        "digest; its fingerprints are not comparable with the ones computed now. " +
        "Run `heldfast approve` to re-record it.",
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

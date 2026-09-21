#!/usr/bin/env node
"use strict";

/**
 * PreToolUse: deny mcp__server__tool when the lock is missing, the server
 * is unpinned, or the tool was not present at approval.
 *
 * Does not rewrite hashes. Does not start the server. A live definition
 * (tool_definition / tool_input._definition) is hashed when present; a
 * mismatch is deny, same as wrap.
 */

const { loadLock, findServerEntry, parseMcpTool, toolDigest, readStdin } = require("./lib.js");

function deny(reason) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: "mcp-pin: " + reason,
    },
  }) + "\n");
  process.exit(0);
}

function allow() {
  process.exit(0);
}

(async () => {
  let event = {};
  try {
    const raw = await readStdin();
    if (raw.trim()) event = JSON.parse(raw);
  } catch (_err) {
    allow();
  }
  const parsed = parseMcpTool(event.tool_name || event.toolName || "");
  if (!parsed) allow();

  const cwd = event.cwd || process.cwd();
  const { path: lockPath, data } = loadLock(cwd);
  if (!lockPath) {
    deny("no .mcp-pin.lock; refusing " + parsed.server + "/" + parsed.tool);
  }
  const entry = findServerEntry(data, parsed.server);
  if (!entry) {
    deny("server '" + parsed.server + "' is not in the lockfile");
  }
  const tools = entry.tools && typeof entry.tools === "object" ? entry.tools : null;
  if (tools && !Object.prototype.hasOwnProperty.call(tools, parsed.tool)) {
    deny("tool '" + parsed.tool + "' was not present at approval");
  }
  const live = event.tool_definition || event.toolDefinition ||
    (event.tool_input && event.tool_input._definition) || null;
  if (live && tools && tools[parsed.tool] && tools[parsed.tool].fingerprint) {
    const pinned = String(tools[parsed.tool].fingerprint);
    const got = toolDigest(Object.assign({ name: parsed.tool }, live));
    if (got !== pinned) {
      deny("tool '" + parsed.tool + "' fingerprint changed since approval");
    }
  }
  allow();
})();

#!/usr/bin/env node
"use strict";

/**
 * PreToolUse: deny mcp__server__tool when the lock is missing, the server
 * is unpinned, or the tool was not present at approval.
 *
 * Does not rewrite hashes. Does not start the server. A live definition
 * (tool_definition / tool_input._definition) is hashed when present; a
 * mismatch is deny, same as wrap.
 *
 * THIS AND `wrap` MUST ANSWER THE SAME QUESTION THE SAME WAY
 * ----------------------------------------------------------
 * They read one lockfile and they are both call-site enforcement, so a state
 * where one denies and the other allows is a hole wearing a second opinion.
 * Three of those were live, and all three had this side being the permissive
 * one:
 *
 *   - a lockfile that would not parse threw out of the async body, which is
 *     an exit code and no decision. `guard.py` says in its own docstring that
 *     an internal error fails closed; this fell open.
 *   - an entry with no `tools` key allowed everything. `_load_locked_tools`
 *     returns `{}` there, and `{}` is an allowlist of nothing, so wrap denies.
 *   - two entries sharing a bare name resolved to whichever came first, so
 *     Cursor's approval governed a Claude Code server. That is the bug
 *     T-DRIFT-ID names and the Python side already refuses.
 *
 * `tests/test_plugin.py` walks a table of lock states and asserts the two
 * agree on every one of them.
 */

const { loadLock, findServerEntry, parseMcpTool, toolDigest, readStdin,
        LOCK_VERSION, DIGEST_CHANGED_IN } = require("./lib.js");

function deny(reason) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: "mcp-pin: " + reason,
    },
  }) + "\n");
  // Not process.exit(): stdout to a pipe can still be draining, and exiting
  // out from under it would drop the denial on the floor. Setting the code
  // lets the event loop finish the write and then leave on its own.
  process.exitCode = 0;
}

function allow() {
  process.exitCode = 0;
}

async function decide(event) {
  const parsed = parseMcpTool(event.tool_name || event.toolName || "");
  if (!parsed) return allow();

  const cwd = event.cwd || process.cwd();
  let lockPath;
  let data;
  try {
    ({ path: lockPath, data } = loadLock(cwd));
  } catch (err) {
    // Unreadable or malformed. The call is refused rather than waved through:
    // "we could not tell" and "it was approved" must not be the same answer.
    return deny("lockfile could not be read (" + String(err && err.message || err) +
      "); refusing " + parsed.server + "/" + parsed.tool);
  }
  if (!lockPath) {
    return deny("no .mcp-pin.lock; refusing " + parsed.server + "/" + parsed.tool);
  }

  const version = Number((data && data.version) || 0);
  if (version > LOCK_VERSION) {
    return deny("lockfile version " + version + " is newer than this hook understands; " +
      "upgrade mcp-pin rather than running against a file it cannot read");
  }
  if (version && version < DIGEST_CHANGED_IN) {
    return deny("lockfile version " + version + " predates the RFC 8785 digest, so its " +
      "fingerprints are not comparable; run `mcp-pin approve` to re-record it");
  }

  const found = findServerEntry(data, parsed.server);
  if (found && found.ambiguous) {
    return deny("'" + parsed.server + "' matches " + found.ambiguous +
      " lockfile entries and this hook cannot tell which one you meant; " +
      "give the servers distinct names or scope the entry");
  }
  const entry = found && found.entry;
  if (!entry) {
    return deny("server '" + parsed.server + "' is not in the lockfile");
  }
  if (entry.conflict) {
    return deny("the lockfile entry for '" + parsed.server + "' covers more than one " +
      "server definition, so it cannot say which was approved; re-run `mcp-pin approve`");
  }

  // No `tools` key means the entry was never probed, so nothing was approved.
  // An empty map means the same thing an empty allowlist always means.
  const tools = entry.tools && typeof entry.tools === "object" ? entry.tools : {};
  if (!Object.prototype.hasOwnProperty.call(tools, parsed.tool)) {
    return deny("tool '" + parsed.tool + "' was not present at approval");
  }

  const live = event.tool_definition || event.toolDefinition ||
    (event.tool_input && event.tool_input._definition) || null;
  if (live && tools[parsed.tool] && tools[parsed.tool].fingerprint) {
    const pinned = String(tools[parsed.tool].fingerprint);
    const got = toolDigest(Object.assign({ name: parsed.tool }, live));
    if (got !== pinned) {
      return deny("tool '" + parsed.tool + "' fingerprint changed since approval");
    }
  }
  return allow();
}

(async () => {
  let event = {};
  try {
    const raw = await readStdin();
    if (raw.trim()) event = JSON.parse(raw);
  } catch (_err) {
    // An unreadable event is not a lock failure: there is no tool name to
    // refuse, and denying every call because stdin hiccuped would take the
    // session down. Nothing is claimed either way.
    return allow();
  }
  await decide(event);
})().catch((err) => {
  // Anything unforeseen above. The last word is still a refusal, because the
  // alternative is a hook that goes quiet exactly when it is confused.
  deny("internal error in the hook (" + String(err && err.message || err) +
    "); refusing rather than allowing an unchecked call");
});

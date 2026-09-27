#!/usr/bin/env node
"use strict";

/**
 * PreToolUse: deny mcp__server__tool when the lock is missing, the server
 * is unpinned, or the tool was not present at approval.
 *
 * Does not rewrite hashes. Does not start the server.
 *
 * NAMES, NOT DEFINITIONS
 * ----------------------
 * A PreToolUse event carries the tool's name, the arguments the model wrote
 * and an id -- never the tool's definition. This hook used to hash a
 * definition when one arrived as `tool_definition`, `toolDefinition` or
 * `tool_input._definition`. The first two never arrive from Claude Code, and
 * no other client this was written for sends them. The third is part of the
 * arguments, which the model writes: it proved nothing about what the server
 * sent, and at most let the model trigger a denial. All three are gone, and
 * with them the graded-drift path they fed. So in Claude Code this checks
 * names. A tool whose definition changed under the same name is caught by
 * `wrap` or `gateway`, which see the server's own tools/list.
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
 *
 * ANOTHER PLUGIN'S SERVERS
 * ------------------------
 * Claude Code names a tool from a plugin-bundled MCP server
 * `mcp__plugin_<plugin>_<server>__<tool>`. `heldfast approve` finds installed
 * plugins' servers and records them as `claude-code-plugin:<plugin>:<server>`,
 * and those are matched like any other. One the lock does not name is refused
 * with what it is and how to approve it. HELDFAST_ALLOW_UNPINNED
 * (comma-separated, matched exactly, e.g. `plugin_other-plugin_db`) lets named
 * ones through, unpinned, and says so on every call.
 */

const { loadLock, findServerEntry, parseMcpTool, resolveMcpTool, readStdin,
        LOCK_VERSION, DIGEST_CHANGED_IN } = require("./lib.js");

const PLUGIN_PREFIX = "mcp__plugin_";

function deny(reason) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: "heldfast: " + reason,
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

/** The override name this plugin tool matches exactly, or "". */
function allowedUnpinned(toolName) {
  const named = String(process.env.HELDFAST_ALLOW_UNPINNED || "")
    .split(",").map((s) => s.trim()).filter((s) => s.startsWith("plugin_"));
  return named.find((server) => toolName.startsWith("mcp__" + server + "__") &&
    toolName.length > ("mcp__" + server + "__").length) || "";
}

function unmatched(toolName) {
  if (toolName.startsWith(PLUGIN_PREFIX)) {
    const server = allowedUnpinned(toolName);
    if (server) {
      process.stderr.write("heldfast: " + toolName + " is called UNPINNED: '" + server +
        "' is another plugin's MCP server, let through by HELDFAST_ALLOW_UNPINNED.\n");
      return allow();
    }
    return deny("'" + toolName + "' is a tool from another Claude Code plugin's MCP " +
      "server, and the lockfile does not name that server. `heldfast approve --probe` " +
      "records installed plugins' servers; or, to call it unpinned, set " +
      "HELDFAST_ALLOW_UNPINNED to its name as it appears after mcp__ " +
      "(plugin_<plugin>_<server>).");
  }
  const named = parseMcpTool(toolName);
  return deny("server '" + (named ? named.server : toolName) + "' is not in the lockfile");
}

async function decide(event) {
  const toolName = String(event.tool_name || event.toolName || "");
  const named = parseMcpTool(toolName);
  if (!named) return allow();

  const cwd = event.cwd || process.cwd();
  let lockPath;
  let data;
  try {
    ({ path: lockPath, data } = loadLock(cwd));
  } catch (err) {
    // Unreadable or malformed. The call is refused rather than waved through:
    // "we could not tell" and "it was approved" must not be the same answer.
    return deny("lockfile could not be read (" + String(err && err.message || err) +
      "); refusing " + named.server + "/" + named.tool);
  }
  if (!lockPath) {
    return deny("no .mcp-pin.lock; refusing " + named.server + "/" + named.tool);
  }

  const version = Number((data && data.version) || 0);
  if (version > LOCK_VERSION) {
    return deny("lockfile version " + version + " is newer than this hook understands; " +
      "upgrade heldfast rather than running against a file it cannot read");
  }
  if (version && version < DIGEST_CHANGED_IN) {
    return deny("lockfile version " + version + " predates the RFC 8785 digest, so its " +
      "fingerprints are not comparable; run `heldfast approve` to re-record it");
  }

  const parsed = resolveMcpTool(toolName, data);
  if (parsed && parsed.ambiguous) {
    return deny("'" + toolName + "' fits " + parsed.ambiguous.length + " servers in the " +
      "lockfile (" + parsed.ambiguous.join(", ") + ") that Claude Code writes the same " +
      "way, so this hook cannot tell which one is being called; give them distinct names");
  }
  if (!parsed) return unmatched(toolName);

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
      "server definition, so it cannot say which was approved; re-run `heldfast approve`");
  }

  // No `tools` key means the entry was never probed, so nothing was approved.
  // An empty map means the same thing an empty allowlist always means.
  const tools = entry.tools && typeof entry.tools === "object" ? entry.tools : {};
  if (!Object.prototype.hasOwnProperty.call(tools, parsed.tool)) {
    return deny("tool '" + parsed.tool + "' was not present at approval");
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

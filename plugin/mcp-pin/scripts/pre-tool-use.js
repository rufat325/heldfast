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
 *
 * GRADED DRIFT (MCP_PIN_DRIFT=graded)
 * -----------------------------------
 * `wrap --drift graded` forwards a changed tool when the change introduced no
 * signal. This hook does the same only by asking `mcp-pin grade-drift`, the
 * same Python the wrap runs, rather than keeping a JavaScript copy of the
 * patterns: two copies of a regex table are two answers waiting to happen.
 * Anything but a clean answer from it -- not installed, timed out, exited
 * non-zero, printed something that is not the expected JSON -- is a deny.
 * Without grading this call was refused, so refusing it is not a new failure.
 */

const { spawnSync } = require("child_process");
const { loadLock, findServerEntry, parseMcpTool, toolDigest, readStdin,
        LOCK_VERSION, DIGEST_CHANGED_IN } = require("./lib.js");

const GRADE_TIMEOUT_MS = 15000;

/** {introduced: [...]} from mcp-pin, or {error: "..."}. Never throws. */
function gradeDrift(recorded, definition) {
  // MCP_PIN_PYTHON runs the module from a given interpreter (a venv, a test);
  // otherwise the `mcp-pin` on PATH, which is what `pipx install` puts there.
  const python = process.env.MCP_PIN_PYTHON;
  const cmd = python || "mcp-pin";
  const args = python ? ["-m", "mcp_pin", "grade-drift"] : ["grade-drift"];
  let proc;
  try {
    proc = spawnSync(cmd, args, {
      input: JSON.stringify({ recorded, definition }),
      encoding: "utf8", timeout: GRADE_TIMEOUT_MS, windowsHide: true,
    });
  } catch (err) {
    return { error: String(err && err.message || err) };
  }
  if (proc.error) return { error: String(proc.error.message || proc.error) };
  if (proc.status !== 0) {
    return { error: "grade-drift exited " + proc.status + ": " +
      String(proc.stderr || "").trim().slice(0, 200) };
  }
  let out;
  try {
    out = JSON.parse(proc.stdout);
  } catch (_err) {
    return { error: "grade-drift printed something that is not JSON" };
  }
  if (!out || !Array.isArray(out.introduced)) {
    return { error: "grade-drift answered without an `introduced` list" };
  }
  return { introduced: out.introduced };
}

function describe(found) {
  const head = found.slice(0, 3).map((s) => String(s.kind) + " '" + String(s.match) + "'");
  return head.join(", ") + (found.length > 3 ? " and " + (found.length - 3) + " more" : "");
}

function driftVerdict(tool, recorded, definition) {
  if (process.env.MCP_PIN_DRIFT !== "graded") {
    return deny("tool '" + tool + "' fingerprint changed since approval");
  }
  const graded = gradeDrift(recorded, definition);
  if (graded.error) {
    return deny("tool '" + tool + "' fingerprint changed since approval, and grading " +
      "the change failed (" + graded.error + "); refusing rather than allowing");
  }
  if (graded.introduced.length) {
    return deny("tool '" + tool + "' fingerprint changed since approval and the change " +
      "introduced " + describe(graded.introduced));
  }
  process.stderr.write("mcp-pin: tool '" + tool + "' changed since approval; the change " +
    "introduced no signal (MCP_PIN_DRIFT=graded). Forwarded, not approved -- " +
    "`mcp-pin approve --probe` pins it.\n");
  return allow();
}

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
    const definition = Object.assign({ name: parsed.tool }, live);
    if (toolDigest(definition) !== pinned) {
      return driftVerdict(parsed.tool, tools[parsed.tool], definition);
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

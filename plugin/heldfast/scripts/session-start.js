#!/usr/bin/env node
"use strict";

/**
 * SessionStart: audit .mcp-pin.lock in the project. Does not launch servers,
 * does not rewrite the lock, does not call a model.
 *
 * With HELDFAST_SESSION_CHECK=1 it also reads, once, each hosted (HTTP)
 * server the lock records -- through `heldfast hosted-drift`, which runs no
 * server code -- and writes the approved tools whose definition changed to a
 * state file for this session. PreToolUse refuses those tools. It is opt-in
 * because it is the one thing this plugin does that reaches the network; a
 * server that wants a login cannot be read and is reported, not refused.
 */

const { spawnSync } = require("child_process");
const { loadLock, readStdin, sessionStatePath, writeSessionState } = require("./lib.js");

const CHECK_TIMEOUT_MS = 25000;

function summary(lock) {
  const servers = lock.servers && typeof lock.servers === "object" ? lock.servers : {};
  let tools = 0;
  for (const entry of Object.values(servers)) {
    if (entry && entry.tools && typeof entry.tools === "object") {
      tools += Object.keys(entry.tools).length;
    }
  }
  const names = Object.keys(servers).map((k) => {
    const e = servers[k];
    return (e && e.name) || k;
  });
  return { n: Object.keys(servers).length, tools, names };
}

/** {servers: {...}} from `heldfast hosted-drift`, or {error: "..."}. Never throws. */
function hostedDrift(lockPath) {
  const python = process.env.MCP_PIN_PYTHON;
  const cmd = python || "heldfast";
  const args = (python ? ["-m", "heldfast"] : []).concat(
    ["hosted-drift", "--lock", lockPath, "--timeout", "5"]);
  let proc;
  try {
    proc = spawnSync(cmd, args, { encoding: "utf8", timeout: CHECK_TIMEOUT_MS, windowsHide: true });
  } catch (err) {
    return { error: String(err && err.message || err) };
  }
  if (proc.error) return { error: String(proc.error.message || proc.error) };
  if (proc.status !== 0) return { error: "hosted-drift exited " + proc.status };
  try {
    const out = JSON.parse(proc.stdout);
    if (out && out.servers && typeof out.servers === "object") return out;
  } catch (_err) { /* fall through */ }
  return { error: "hosted-drift printed something that is not its JSON" };
}

function sessionCheck(event, lockPath) {
  const found = hostedDrift(lockPath);
  if (found.error) {
    process.stdout.write("heldfast: hosted servers were not read at session start (" +
      found.error + "); their definitions are not checked this session.\n");
    return;
  }
  const drifted = {};
  const unread = [];
  let read = 0;
  for (const [key, row] of Object.entries(found.servers)) {
    if (!row || row.state !== "read") { unread.push(key); continue; }
    read += 1;
    if (Array.isArray(row.drifted) && row.drifted.length) drifted[key] = row.drifted;
  }
  writeSessionState(event.session_id, { lock: lockPath, drifted });
  const changed = Object.entries(drifted).map(([k, tools]) => k + ": " + tools.join(", "));
  process.stdout.write("heldfast: read " + read + " hosted server(s) at session start" +
    (changed.length ? "; changed since approval, refused this session: " + changed.join("; ")
      : "; no approved tool changed") +
    (unread.length ? ". Not verified (a login, or no answer): " + unread.join(", ") : "") +
    ".\n");
}

(async () => {
  let event = {};
  try {
    const raw = await readStdin();
    if (raw.trim()) event = JSON.parse(raw);
  } catch (_err) {
    event = {};
  }
  const cwd = event.cwd || process.cwd();
  const { path: lockPath, data } = loadLock(cwd);
  if (!lockPath) {
    process.stdout.write(
      "heldfast: no .mcp-pin.lock in " + cwd +
        ". MCP tool calls will be refused until you `heldfast approve --probe`.\n"
    );
    process.exit(0);
  }
  const s = summary(data);
  process.stdout.write(
    "heldfast: " + lockPath + " — " + s.n + " server(s), " + s.tools +
      " tool(s) pinned" + (s.names.length ? " (" + s.names.join(", ") + ")" : "") + ".\n"
  );
  if (process.env.MCP_PIN_DRIFT === "graded") {
    process.stdout.write(
      "heldfast: MCP_PIN_DRIFT=graded has no effect here. Claude Code gives this hook a " +
        "tool's name, not its definition, so it checks names; `heldfast wrap --drift graded` " +
        "sees the definitions.\n"
    );
  }
  if (process.env.HELDFAST_SESSION_CHECK === "1" && event.session_id) {
    sessionCheck(event, lockPath);
  } else if (sessionStatePath(event.session_id)) {
    // A resumed session keeps no state from an earlier check it did not run.
    writeSessionState(event.session_id, { lock: lockPath, drifted: {} });
  }
})();

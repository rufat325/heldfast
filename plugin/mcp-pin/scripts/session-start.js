#!/usr/bin/env node
"use strict";

/**
 * SessionStart: audit .mcp-pin.lock in the project. Does not launch servers,
 * does not rewrite the lock, does not call a model.
 */

const { loadLock, readStdin } = require("./lib.js");

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
      "mcp-pin: no .mcp-pin.lock in " + cwd +
        ". MCP tool calls will be refused until you `mcp-pin approve --probe`.\n"
    );
    process.exit(0);
  }
  const s = summary(data);
  process.stdout.write(
    "mcp-pin: " + lockPath + " — " + s.n + " server(s), " + s.tools +
      " tool(s) pinned" + (s.names.length ? " (" + s.names.join(", ") + ")" : "") + ".\n"
  );
})();

"use strict";

/**
 * The JS half of tests/test_orgpolicy_parity.py. Reads a batch of inputs as
 * JSON on stdin and prints what plugin/heldfast/scripts/orgpolicy.js answers
 * for each, in the same shape the Python half produces, so the test can hold
 * the two to one answer.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const org = require(path.join(__dirname, "..", "..", "plugin", "heldfast", "scripts", "orgpolicy.js"));

function attempt(fn) {
  try {
    return fn();
  } catch (_err) {
    return "ERROR";
  }
}

const input = JSON.parse(fs.readFileSync(0, "utf8"));
const out = {};
out.glob = (input.glob || []).map(([t, p]) => org.glob(t, p));
out.endpoint = (input.endpoint || []).map((u) => org.endpoint(u));
out.shlex = (input.shlex || []).map((t) => attempt(() => org.shlexSplit(t)));
out.describe = (input.describe || []).map((s) => org.describe(s));
out.lock = (input.lock || []).map((e) => org.describe(org.specFromLock(e)));
out.config = (input.config || []).map((e) => org.describe(org.specFromConfig(e)));
out.parse = (input.parse || []).map((p) => attempt(() => (org.parsePolicy(p), "ok")));
out.load = (input.load || []).map((text) => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "heldfast-org-")), "p.json");
  fs.writeFileSync(file, Buffer.from(text, "base64"));
  return attempt(() => (org.load(file), "ok"));
});
out.refusal = (input.refusal || []).map(({ policy, spec, entry }) => attempt(() => {
  const parsed = org.parsePolicy(policy, "0".repeat(64));
  const row = Object.assign(org.describe(org.specFromConfig(spec)), { identity: "claude-code:s" });
  return org.launchRefusal(parsed, row, entry === undefined ? null : entry);
}));
process.stdout.write(JSON.stringify(out));

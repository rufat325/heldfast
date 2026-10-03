"use strict";

/**
 * The organisation policy, read the way `heldfast wrap` reads it.
 *
 * `src/heldfast/orgpolicy.py` decides whether a policy refuses a server, and
 * `src/heldfast/inventory.py` says what a server is -- its package, version,
 * address or command. This is both of them again, for the PreToolUse hook,
 * which runs on every MCP call and must not need Python or a state file an
 * agent could rewrite. A state where `wrap` refuses a server and this lets
 * Claude Code call it is a hole wearing a second opinion, so every function
 * here is held to the Python by `tests/golden/orgpolicy/vectors.json` and by a
 * seeded differential test that feeds both the same random inputs
 * (T-ORG-PARITY).
 *
 * Where the Python leans on Python's own semantics -- str.strip(), `\s` and
 * `\d` in a str pattern, shlex.split() -- they are spelt out here rather than
 * approximated by the JS built-ins, which differ at the edges.
 */

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const SCHEMA = "heldfast.org-policy/1";
const ENV_VAR = "HELDFAST_ORG_POLICY";
const MANAGED_PATHS = {
  linux: "/etc/heldfast/org-policy.json",
  darwin: "/Library/Application Support/heldfast/org-policy.json",
  win32: "%ProgramData%\\heldfast\\org-policy.json",
};

const TOP_KEYS = new Set(["policy", "name", "allow", "deny", "unlisted", "require", "description"]);
const RULE_KEYS = new Set(["package", "versions", "url", "command", "kind", "reason"]);
const REQUIRE_KEYS = new Set(["approved", "pinned", "exact_versions", "enforced", "no_drift", "fail_on"]);
const KINDS = new Set(["hosted", "package", "local"]);
const UNLISTED = new Set(["allow", "warn", "deny"]);
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const ECOSYSTEMS = new Set(["npm", "pypi", "*"]);
const PINNED_KEYS = ["tools", "prompts", "resources", "instructions"];

// ---------------------------------------------------------------------------
// Python's semantics, spelt out

// Every character str.isspace() is true for, which is also what `\s` matches
// in a Python str pattern. JS's own \s and trim() differ on \x1c-\x1f.
const PY_SPACE = "\\t\\n\\u000b\\u000c\\r\\u001c-\\u001f \\u0085\\u00a0\\u1680\\u2000-\\u200a" +
  "\\u2028\\u2029\\u202f\\u205f\\u3000";
const PY_SPACE_RE = new RegExp("[" + PY_SPACE + "]", "u");
const ASCII_SPACE = new Set([" ", "\t", "\n", "\r", "\u000b", "\u000c"]);

function chars(text) {
  return Array.from(String(text));
}

function stripSet(text, isStripped) {
  const cs = chars(text);
  let a = 0;
  let b = cs.length;
  while (a < b && isStripped(cs[a])) a += 1;
  while (b > a && isStripped(cs[b - 1])) b -= 1;
  return cs.slice(a, b).join("");
}

/** str.strip() with no argument. */
function pyStrip(text) {
  return stripSet(text, (c) => PY_SPACE_RE.test(c));
}

/** str.strip(" \t\n\r\x0b\x0c"). */
function asciiStrip(text) {
  return stripSet(text, (c) => ASCII_SPACE.has(c));
}

/** str.lstrip(chars). */
function lstrip(text, set) {
  const cs = chars(text);
  let a = 0;
  while (a < cs.length && set.includes(cs[a])) a += 1;
  return cs.slice(a).join("");
}

/** secrets.safe_name: control characters escaped, newlines too, length capped. */
function safeName(value, limit = 300) {
  let cs = chars(value === null || value === undefined ? "" : value);
  let text = cs.length > limit ? cs.slice(0, limit).join("") + "..." : cs.join("");
  text = text.replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g,
    (c) => "\\x" + c.charCodeAt(0).toString(16).padStart(2, "0"));
  return text.replace(/\n/g, "\\n").replace(/\r/g, "\\r");
}

/** Python truthiness, for the lock entry values `pinned` asks about. */
function truthy(value) {
  if (value === null || value === undefined || value === false || value === 0 || value === "") {
    return false;
  }
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value).length > 0;
  return true;
}

/**
 * shlex.split(text) -- POSIX mode, no comments. Throws where Python raises
 * ValueError (an unclosed quote, a trailing backslash).
 */
function shlexSplit(text) {
  const WHITESPACE = " \t\r\n";
  const out = [];
  const cs = chars(text);
  let i = 0;
  for (;;) {
    let token = "";
    let quoted = false;
    let state = " ";
    let escapedstate = " ";
    let emitted = false;
    while (!emitted) {
      const c = i < cs.length ? cs[i] : "";
      i += 1;
      if (state === " ") {
        if (!c) { state = null; break; }
        if (WHITESPACE.includes(c)) {
          if (token || quoted) { emitted = true; break; }
          continue;
        }
        if (c === "\\") { escapedstate = "a"; state = c; }
        else if (c === "'" || c === "\"") { state = c; }
        else { token = c; state = "a"; }
      } else if (state === "'" || state === "\"") {
        quoted = true;
        if (!c) throw new Error("No closing quotation");
        if (c === state) state = "a";
        else if (c === "\\" && state === "\"") { escapedstate = state; state = c; }
        else token += c;
      } else if (state === "\\") {
        if (!c) throw new Error("No escaped character");
        if ((escapedstate === "'" || escapedstate === "\"") && c !== state && c !== escapedstate) {
          token += state;
        }
        token += c;
        state = escapedstate;
      } else {
        if (!c) { state = null; break; }
        if (WHITESPACE.includes(c)) {
          state = " ";
          if (token || quoted) { emitted = true; break; }
          continue;
        }
        if (c === "'" || c === "\"") state = c;
        else if (c === "\\") { escapedstate = "a"; state = c; }
        else token += c;
      }
    }
    if (!emitted && !quoted && token === "") return out;
    out.push(token);
    if (!emitted) return out;
  }
}

// ---------------------------------------------------------------------------
// Matching (orgpolicy.py)

/** `*` any run of characters, `?` any one, nothing else special. Linear. */
function glob(text, pattern) {
  const t = chars(text);
  const p = chars(pattern);
  let ti = 0;
  let pi = 0;
  let star = -1;
  let mark = 0;
  while (ti < t.length) {
    if (pi < p.length && p[pi] !== "*" && (p[pi] === "?" || p[pi] === t[ti])) {
      ti += 1; pi += 1;
    } else if (pi < p.length && p[pi] === "*") {
      star = pi; mark = ti; pi += 1;
    } else if (star >= 0) {
      pi = star + 1; mark += 1; ti = mark;
    } else {
      return false;
    }
  }
  while (pi < p.length && p[pi] === "*") pi += 1;
  return pi === p.length;
}

function pep503(name) {
  return String(name).replace(/[-_.]+/g, "-").toLowerCase();
}

const URL_PATTERN = /^([A-Za-z*][A-Za-z0-9+.*-]*):\/\/([^/?#]+)(\/[^?#]*)?$/;

/** [scheme, host, port|null, path|null] of a URL or URL pattern, or null. */
function urlParts(text) {
  const m = URL_PATTERN.exec(asciiStrip(text));
  if (!m) return null;
  let host = m[2].toLowerCase();
  if (host.includes("@")) return null;
  let port = null;
  if (host.startsWith("[")) {
    const end = host.indexOf("]");
    if (end < 0) return null;
    const rest = host.slice(end + 1);
    host = host.slice(0, end + 1);
    if (rest) {
      if (!rest.startsWith(":")) return null;
      port = rest.slice(1);
    }
  } else if ((host.match(/:/g) || []).length === 1) {
    [host, port] = host.split(":");
  }
  return [m[1].toLowerCase(), host, port, m[3] === undefined ? null : m[3]];
}

function packageMatches(rule, pkg) {
  if (!pkg) return false;
  const at = rule.package.indexOf(":");
  const eco = rule.package.slice(0, at).toLowerCase();
  const pattern = rule.package.slice(at + 1);
  if (eco !== "*" && eco !== pkg.ecosystem) return false;
  const name = String(pkg.name || "");
  if (pkg.ecosystem === "pypi") return glob(pep503(name), pep503(pattern));
  return glob(name, pattern);
}

function versionsMatch(rule, pkg, deny) {
  if (!rule.versions.length) return true;
  if (!pkg.exact) return deny;
  const version = String(pkg.version || "");
  return rule.versions.some((pattern) => glob(version, pattern));
}

function urlMatches(rule, endpoint) {
  const want = urlParts(rule.url);
  const got = urlParts(endpoint);
  if (!want || !got) return false;
  const [scheme, host, port, p] = want;
  if (!glob(got[0], scheme) || !glob(got[1], host)) return false;
  if (port !== null && !glob(got[2] || "", port)) return false;
  return p === null || glob(got[3] || "/", p);
}

function matches(rule, row, deny = false) {
  if (rule.kind && rule.kind !== row.kind) return false;
  if (rule.command && !glob(String(row.command || ""), rule.command.toLowerCase())) return false;
  if (rule.url) {
    if (!row.endpoint) {
      if (!(deny && row.kind === "hosted")) return false;
    } else if (!urlMatches(rule, String(row.endpoint))) {
      return false;
    }
  }
  if (rule.package) {
    if (!packageMatches(rule, row.package)) return false;
    if (!versionsMatch(rule, row.package || {}, deny)) return false;
  }
  return true;
}

function describeRule(rule) {
  const parts = [["package", rule.package], ["url", rule.url], ["command", rule.command],
    ["kind", rule.kind]].filter(([, v]) => v).map(([k, v]) => k + " " + v);
  if (rule.versions.length) parts.push("versions " + rule.versions.join(", "));
  return parts.join("; ");
}

function what(row) {
  const pkg = row.package;
  if (pkg) return pkg.version ? pkg.name + "@" + pkg.version : String(pkg.name);
  return String(row.endpoint || row.command || row.identity);
}

function denied(policy, row) {
  for (const rule of policy.deny) {
    if (!matches(rule, row, true)) continue;
    let why = rule.reason || "matches deny rule (" + describeRule(rule) + ")";
    const pkg = row.package || {};
    if (rule.versions.length && row.package && !pkg.exact) {
      why += "; no exact version is pinned, so it may run a denied release";
    }
    if (rule.url && !row.endpoint) {
      why += "; its address cannot be read unambiguously, so it may be the denied one";
    }
    return what(row) + " is denied: " + why;
  }
  return null;
}

function unlistedLevel(policy, row) {
  if (!policy.allow.length || policy.unlisted === "allow") return null;
  if (policy.allow.some((rule) => matches(rule, row))) return null;
  return policy.unlisted;
}

/** orgpolicy.launch_refusal: why `policy` refuses this server, or null. */
function launchRefusal(policy, row, entry) {
  const head = "organisation policy " + (policy.name || "(unnamed)") + " (sha256:" +
    policy.digest.slice(0, 12) + ") refuses this server: ";
  const deny = denied(policy, row);
  if (deny !== null) return head + deny;
  if (unlistedLevel(policy, row) === "deny") return head + what(row) + " is not on the allow list";
  const need = policy.require;
  if (need.approved && entry === null) {
    return head + "it requires every server to be approved in a lockfile, and " +
      "--allow-unapproved cannot waive that";
  }
  if (need.pinned && entry !== null && !PINNED_KEYS.some((k) => truthy(entry[k]))) {
    return head + "it requires tool definitions to be pinned, and this approval pins none";
  }
  const pkg = row.package;
  if (need.exact_versions && pkg && !pkg.exact) {
    return head + pkg.name + " runs whatever was published last, and it requires an exact version";
  }
  return null;
}

// ---------------------------------------------------------------------------
// Reading a policy (orgpolicy.parse)

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function text(value, where) {
  if (typeof value !== "string") throw new Error(where + ": expected a string");
  return value;
}

function parseRule(item, where) {
  if (!isObject(item)) throw new Error(where + ": a rule is an object");
  const unknown = Object.keys(item).filter((k) => !RULE_KEYS.has(k)).sort();
  if (unknown.length) throw new Error(where + ": unknown key(s) " + unknown.join(", "));
  const versions = "versions" in item ? item.versions : [];
  if (!Array.isArray(versions) || !versions.every((v) => typeof v === "string" && v)) {
    throw new Error(where + ": versions must be a list of version globs");
  }
  const rule = {
    package: text("package" in item ? item.package : "", where + ".package"),
    versions,
    url: text("url" in item ? item.url : "", where + ".url"),
    command: text("command" in item ? item.command : "", where + ".command"),
    kind: text("kind" in item ? item.kind : "", where + ".kind"),
    reason: text("reason" in item ? item.reason : "", where + ".reason"),
  };
  if (!(rule.package || rule.url || rule.command || rule.kind)) {
    throw new Error(where + ": a rule needs a package, url, command or kind");
  }
  if (rule.versions.length && !rule.package) {
    throw new Error(where + ": versions only mean something beside a package");
  }
  if (rule.package) {
    const at = rule.package.indexOf(":");
    if (at < 0 || !ECOSYSTEMS.has(rule.package.slice(0, at).toLowerCase()) ||
        !rule.package.slice(at + 1)) {
      throw new Error(where + ": package is <npm|pypi|*>:<name glob>");
    }
  }
  if (rule.url && urlParts(rule.url) === null) {
    throw new Error(where + ": url is <scheme>://<host glob>[/<path glob>]");
  }
  if (rule.kind && !KINDS.has(rule.kind)) throw new Error(where + ": kind is hosted, local or package");
  return rule;
}

function parseRules(value, where) {
  if (!Array.isArray(value)) throw new Error("\"" + where + "\" must be a list of rules");
  return value.map((item, i) => parseRule(item, where + "[" + i + "]"));
}

function parseRequire(value) {
  if (!isObject(value)) throw new Error("\"require\" must be an object");
  const unknown = Object.keys(value).filter((k) => !REQUIRE_KEYS.has(k)).sort();
  if (unknown.length) throw new Error("require: unknown key(s) " + unknown.join(", "));
  for (const [key, flag] of Object.entries(value)) {
    if (key === "fail_on") {
      if (typeof flag !== "string" || !SEVERITIES.includes(flag)) {
        throw new Error("require.fail_on is one of " + SEVERITIES.join(", "));
      }
    } else if (typeof flag !== "boolean") {
      throw new Error("require." + key + " must be true or false");
    }
  }
  return Object.assign({}, value);
}

/** orgpolicy.parse. Throws on anything the Python refuses. */
function parsePolicy(data, digest = "") {
  if (!isObject(data)) throw new Error("a policy is a JSON object");
  const unknown = Object.keys(data).filter((k) => !TOP_KEYS.has(k)).sort();
  if (unknown.length) {
    throw new Error("unknown key(s) " + unknown.join(", ") +
      "; refusing a policy this version would only partly enforce");
  }
  if (data.policy !== SCHEMA) throw new Error("\"policy\" must be \"" + SCHEMA + "\"");
  const unlisted = "unlisted" in data ? data.unlisted : "warn";
  if (typeof unlisted !== "string" || !UNLISTED.has(unlisted)) {
    throw new Error("\"unlisted\" must be one of allow, deny, warn");
  }
  return {
    name: text("name" in data ? data.name : "", "name"),
    allow: parseRules("allow" in data ? data.allow : [], "allow"),
    deny: parseRules("deny" in data ? data.deny : [], "deny"),
    unlisted,
    require: parseRequire("require" in data ? data.require : {}),
    digest,
  };
}

function load(file) {
  let raw;
  try {
    raw = fs.readFileSync(file);
  } catch (err) {
    throw new Error(file + ": cannot read policy (" + String(err && err.message || err) + ")");
  }
  let data;
  try {
    // ignoreBOM keeps a BOM in the text, so JSON.parse refuses it as json.loads does.
    data = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw));
  } catch (err) {
    throw new Error(file + ": not JSON (" + String(err && err.message || err) + ")");
  }
  try {
    return parsePolicy(data, crypto.createHash("sha256").update(raw).digest("hex"));
  } catch (err) {
    throw new Error(file + ": " + String(err && err.message || err));
  }
}

/** orgpolicy.managed_path. */
function managedPath(platform = process.platform, env = process.env) {
  const key = /^(linux|freebsd|openbsd|netbsd)/.test(platform) ? "linux" : platform;
  const raw = MANAGED_PATHS[key];
  if (!raw) return null;
  return raw.replace(/%([^%]+)%/g, (whole, name) =>
    Object.prototype.hasOwnProperty.call(env, name) ? env[name] : whole);
}

/**
 * orgpolicy.for_launch: [{policy, where}] for every policy a call must meet.
 * Throws when one that is there cannot be read; the caller refuses.
 */
function forLaunch(env = process.env, platform = process.platform) {
  const found = [];
  const managed = managedPath(platform, env);
  if (managed) {
    let present = false;
    try {
      fs.statSync(managed);
      present = true;
    } catch (err) {
      if (!err || (err.code !== "ENOENT" && err.code !== "ENOTDIR")) {
        throw new Error(managed + ": the managed policy cannot be checked (" +
          String(err && err.message || err) + ")");
      }
    }
    if (present) found.push({ policy: load(managed), where: managed });
  }
  const named = env[ENV_VAR];
  if (named) found.push({ policy: load(named), where: named });
  return found;
}

// ---------------------------------------------------------------------------
// What a server is (inventory.py, enforcement.py, rules/execution.py)

const SELF = new Set(["heldfast", "heldfast.exe"]);
const WRAPPING = new Set(["guard", "wrap"]);
const RUNNERS = new Set(["npx", "bunx", "pnpx", "uvx", "pipx", "yarn", "pnpm", "deno", "bun"]);
const FLAGS_WITH_VALUE = new Set(["--package", "-p", "--from", "--with", "--node-range", "--registry"]);
const RUNNER_SUBCOMMANDS = new Set(["dlx", "run", "exec", "x"]);
const PYTHON_RUNNERS = new Set(["uvx", "pipx"]);
const ECOSYSTEM = { npx: "npm", pnpx: "npm", bunx: "npm", yarn: "npm", pnpm: "npm", bun: "npm",
  uvx: "pypi", pipx: "pypi" };
// `\d` in a Python str pattern is any Unicode decimal digit.
const FLOATING = /^(?:latest|next|canary|beta|alpha|\*|x|\^|~(?!=)|>=|<=|~=|!=|>|<|\p{Nd}+\.x|\p{Nd}+\.\p{Nd}+\.x)/u;
const PEP508_SPLIT = /(===|==|>=|<=|~=|!=|>|<)/;
const EXACT_NPM = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?$/;
const EXACT_PYPI = /^===?[ \t]*[0-9A-Za-z][0-9A-Za-z.!+_-]*$/;
const OPAQUE = /^(?=.*[0-9])(?=.*[A-Za-z])[A-Za-z0-9_\-.~%=]{20,}$/;
const ABSOLUTE = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)/;
const AUTHORITY = /^[A-Za-z0-9._~!$&'()*+,;=:@[\]-]*$/;
const IPV6 = /^\[[0-9A-Fa-f:.]+\]$/;
const REDACTED = "{redacted}";

// secrets.TOKEN_PATTERNS and the three positional patterns, for the one
// question endpoint() asks: would redact() change this path segment?
const TOKEN_PATTERNS = [
  /sk-ant-[A-Za-z0-9_\-]{20,}/, /sk-(?:proj-)?[A-Za-z0-9_\-]{32,}/, /gh[pousr]_[A-Za-z0-9]{36,}/,
  /github_pat_[A-Za-z0-9_]{60,}/, /glpat-[A-Za-z0-9_\-]{20,}/, /xox[baprs]-[A-Za-z0-9\-]{10,}/,
  /xapp-[0-9]-[A-Za-z0-9\-]{10,}/, /(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}/, /AIza[0-9A-Za-z_\-]{35}/,
  /ya29\.[0-9A-Za-z_\-]{20,}/, /(?:sk|rk)_live_[0-9A-Za-z]{20,}/,
  /SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}/, /npm_[A-Za-z0-9]{36}/, /dop_v1_[a-f0-9]{64}/,
  /hf_[A-Za-z0-9]{30,}/, /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/,
  /eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/,
];
const SECRET_NAME = "(?:[A-Za-z0-9]*[_\\-])?(?:token|secret|password|passwd|pwd|api[_\\-]?key|" +
  "apikey|access[_\\-]?key|auth|key|sig|signature|credential|session)";
const QUERY_SECRET = new RegExp("([?&;]" + SECRET_NAME + "=)([^&#" + PY_SPACE + "]+)", "giu");
const FLAG_SECRET = new RegExp("((?:^|[" + PY_SPACE + "])--?" + SECRET_NAME + "(?:=|[" +
  PY_SPACE + "]+))([^" + PY_SPACE + "-][^" + PY_SPACE + "]*)", "giu");

// redact()'s user:password@ pattern needs `://`, which a path segment never
// holds, so it cannot change one and is not repeated here.
function redactChanges(segment) {
  if (TOKEN_PATTERNS.some((re) => re.test(segment))) return true;
  for (const re of [QUERY_SECRET, FLAG_SECRET]) {
    re.lastIndex = 0;
    for (const m of segment.matchAll(re)) {
      if (!m[2].startsWith("[REDACTED")) return true;
    }
  }
  return false;
}

function hostport(authority) {
  if (!AUTHORITY.test(authority) || (authority.match(/@/g) || []).length > 1) return null;
  const hp = authority.slice(authority.lastIndexOf("@") + 1);
  let host;
  let port;
  if (hp.startsWith("[")) {
    const end = hp.indexOf("]");
    host = hp.slice(0, end + 1);
    const rest = hp.slice(end + 1);
    if (end < 0 || !IPV6.test(host) || (rest && !rest.startsWith(":"))) return null;
    port = rest ? rest.slice(1) : null;
  } else {
    if (hp.includes("[") || hp.includes("]") || (hp.match(/:/g) || []).length > 1) return null;
    const at = hp.indexOf(":");
    host = at < 0 ? hp : hp.slice(0, at);
    port = at < 0 ? null : hp.slice(at + 1);
  }
  if (!host) return null;
  if (port === "") port = null;
  if (port !== null) {
    if (!/^[0-9]+$/.test(port) || Number(port) > 65535) return null;
    port = String(Number(port));
  }
  return [host.toLowerCase(), port];
}

/** inventory.endpoint: an address to match a policy on, or null. */
function endpoint(url) {
  if (!url) return null;
  const t = asciiStrip(url);
  if (t.includes("\\") || /[\x00-\x20\x7f]/.test(t)) return null;
  const m = ABSOLUTE.exec(t);
  if (!m) return null;
  const [, scheme, authority, rawPath] = m;
  const found = hostport(authority);
  if (found === null || rawPath.includes("%") ||
      rawPath.split("/").some((seg) => seg === "." || seg === "..")) {
    return null;
  }
  const [host, port] = found;
  let p = rawPath.split("/").map((seg) =>
    seg && (OPAQUE.test(seg) || redactChanges(seg)) ? REDACTED : seg).join("/");
  if (!p.startsWith("/")) p = "/" + p;
  return scheme.toLowerCase() + "://" + host + (port !== null ? ":" + port : "") + p;
}

function leaf(command) {
  const parts = String(command).replace(/\\/g, "/").split("/");
  return parts[parts.length - 1];
}

/** rules.execution._basename. */
function basename(command) {
  let base = leaf(command).toLowerCase();
  for (const suffix of [".exe", ".cmd", ".bat", ".ps1"]) {
    if (base.endsWith(suffix)) base = base.slice(0, -suffix.length);
  }
  return base;
}

/** enforcement.unwrap_launcher: see through `cmd /c <runner> ...`. */
function unwrapLauncher(command, args) {
  const base = leaf(command || "").toLowerCase();
  if ((base === "cmd" || base === "cmd.exe") && args.length) {
    const rest = args.map(String);
    if ((rest[0].toLowerCase() === "/c" || rest[0].toLowerCase() === "/k") && rest.length > 1) {
      return [rest[1], rest.slice(2)];
    }
  }
  return [command, args.slice()];
}

/** enforcement.subcommand. */
function subcommand(spec) {
  const [command, args] = unwrapLauncher(spec.command || "", spec.args || []);
  let seenSelf = false;
  for (const token of [command].concat(args.map(String))) {
    const t = lstripRstrip(lstripRstrip(pyStrip(token || ""), "\""), "'");
    if (!t) continue;
    if (SELF.has(leaf(t))) { seenSelf = true; continue; }
    if (seenSelf && t === "--") return "wrap";
    if (seenSelf && !t.startsWith("-")) return t;
  }
  return "";
}

function lstripRstrip(textValue, ch) {
  return stripSet(textValue, (c) => c === ch);
}

/** inventory.inner: what a `heldfast wrap ... -- <server>` entry runs. */
function inner(spec) {
  if (!WRAPPING.has(subcommand(spec))) return spec;
  const [command, args] = unwrapLauncher(spec.command || "", spec.args || []);
  const argv = [command].concat(args.map(String));
  const at = argv.indexOf("--");
  if (at < 0) return spec;
  const rest = argv.slice(at + 1);
  if (!rest.length) return spec;
  return { transport: spec.transport, command: rest[0], args: rest.slice(1), url: null };
}

/** rules.execution.extract_package: [runner, token] or null. */
function extractPackage(spec) {
  if (!spec.command) return null;
  const [command, args] = unwrapLauncher(spec.command, spec.args || []);
  const base = basename(command);
  if (!RUNNERS.has(base)) return null;
  let i = 0;
  while (i < args.length) {
    const tok = args[i];
    if (FLAGS_WITH_VALUE.has(tok)) { i += 2; continue; }
    if (tok.startsWith("-")) { i += 1; continue; }
    if (RUNNER_SUBCOMMANDS.has(tok)) { i += 1; continue; }
    return [base, tok];
  }
  return null;
}

function partition(textValue, sep) {
  const at = textValue.indexOf(sep);
  return at < 0 ? [textValue, "", ""] : [textValue.slice(0, at), sep, textValue.slice(at + sep.length)];
}

/** rules.execution.split_package: [name, version|null]. */
function splitPackage(pkg, runner) {
  if (PYTHON_RUNNERS.has(runner)) {
    const m = PEP508_SPLIT.exec(pkg);
    if (!m) return [pyStrip(pkg.split("[")[0]), null];
    return [pyStrip(pkg.slice(0, m.index).split("[")[0]), pyStrip(pkg.slice(m.index))];
  }
  if (pkg.startsWith("@")) {
    const [scope, sep, rest] = partition(pkg, "/");
    if (!sep) return [pkg, null];
    const [name, at, ver] = partition(rest, "@");
    return [scope + "/" + name, at ? ver : null];
  }
  const [name, at, ver] = partition(pkg, "@");
  return [name, at ? ver : null];
}

/** inventory.exact. */
function exact(version, ecosystem) {
  if (!version || FLOATING.test(version)) return false;
  if (ecosystem === "pypi") return EXACT_PYPI.test(version) && !version.includes("*");
  return EXACT_NPM.test(lstrip(version, "=v"));
}

/** inventory.package_of. */
function packageOf(spec) {
  const found = extractPackage(spec);
  if (!found) return null;
  let [runner, token] = found;
  if (runner === "deno") {
    if (!token.startsWith("npm:")) return null;
    runner = "npx";
    token = token.slice(4);
  }
  if (/^[./~]/.test(token) || /^[a-zA-Z]:[\\/]/.test(token)) return null;
  const ecosystem = ECOSYSTEM[runner];
  if (!ecosystem) return null;
  const [name, specVersion] = splitPackage(token, runner);
  if (!name) return null;
  const pinned = exact(specVersion, ecosystem);
  let version = pyStrip(specVersion || "");
  if (pinned) {
    version = PYTHON_RUNNERS.has(runner) ? pyStrip(lstrip(version, "=")) : lstrip(version, "=v");
  }
  return { ecosystem, name: safeName(name), version: safeName(version), exact: pinned };
}

function isRemote(spec) {
  return spec.transport === "http" || spec.transport === "sse" || Boolean(spec.url);
}

/** inventory.describe, for {transport, command, args, url}. */
function describe(spec) {
  const run = inner(spec);
  let command = null;
  if (!isRemote(run) && run.command) {
    command = safeName(basename(unwrapLauncher(run.command, run.args || [])[0]));
  }
  const pkg = packageOf(run);
  return {
    kind: isRemote(run) ? "hosted" : (pkg ? "package" : "local"),
    transport: safeName(spec.transport),
    package: pkg,
    endpoint: run.url ? safeName(endpoint(run.url)) : null,
    command,
  };
}

/** str(value) for a JSON value, as parse_config applies it. */
function pyStr(value) {
  if (value === true) return "True";
  if (value === false) return "False";
  if (value === null || value === undefined) return "None";
  return typeof value === "string" ? value : JSON.stringify(value);
}

/** Python's `a or b or ...`: the first truthy value, else the last. */
function pyOr(...values) {
  for (const value of values) if (truthy(value)) return value;
  return values[values.length - 1];
}

/** inventory._spec_from_lock, as the spec describe() takes. */
function specFromLock(entry) {
  const e = isObject(entry) ? entry : {};
  let argv = [];
  try {
    argv = shlexSplit(pyStr(pyOr(e.command_line, "")));
  } catch (_err) {
    argv = [];
  }
  return {
    transport: pyStr(pyOr(e.transport, "unknown")),
    command: argv.length ? argv[0] : null,
    args: argv.slice(1),
    url: typeof e.url === "string" ? e.url : null,
  };
}

/** parsers._infer_transport. */
function inferTransport(entry) {
  const declared = pyStr(pyOr(entry.type, entry.transport, "")).toLowerCase();
  if (declared === "stdio" || declared === "sse") return declared;
  if (["http", "streamable-http", "streamablehttp", "https"].includes(declared)) return "http";
  if (truthy(entry.command)) return "stdio";
  const url = pyOr(entry.url, entry.serverUrl, entry.endpoint);
  if (truthy(url)) return pyStr(url).toLowerCase().includes("sse") ? "sse" : "http";
  return "unknown";
}

/** A Claude Code config entry as the spec describe() takes (parse_config). */
function specFromConfig(entry) {
  let args = pyOr(entry.args, []);
  if (!Array.isArray(args)) args = [pyStr(args)];
  const url = pyOr(entry.url, entry.serverUrl, entry.endpoint);
  return {
    transport: inferTransport(entry),
    command: truthy(entry.command) ? pyStr(entry.command) : null,
    args: args.map(pyStr),
    url: truthy(url) ? pyStr(url) : null,
  };
}

// ---------------------------------------------------------------------------
// The hook's question

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (_err) {
    return null;
  }
}

/**
 * Where Claude Code itself configures `name` for a project: its own
 * `.mcp.json`, and `~/.claude.json` at user scope and for this directory.
 * Each one found is checked, so a lock that approved one launch cannot speak
 * for a config that now starts another under the same name.
 */
function configuredEntries(name, cwd, home) {
  const out = [];
  const project = readJson(path.join(cwd, ".mcp.json"));
  const user = readJson(path.join(home, ".claude.json"));
  const maps = [project && project.mcpServers, user && user.mcpServers,
    user && isObject(user.projects) && isObject(user.projects[cwd]) && user.projects[cwd].mcpServers];
  for (const map of maps) {
    if (isObject(map) && isObject(map[name])) out.push(map[name]);
  }
  return out;
}

/**
 * Why the organisation forbids calling the server behind this lock entry,
 * or null. Asked of what the lock approved and of every configuration that
 * starts a server by that name, and refused if any is refused.
 */
function refusalFor(policies, key, entry, cwd, home = os.homedir()) {
  if (!policies.length) return null;
  const specs = [specFromLock(entry)];
  if (String(key).startsWith("claude-code:")) {
    for (const configured of configuredEntries(String(entry.name || key.slice(12)), cwd, home)) {
      specs.push(specFromConfig(configured));
    }
  }
  for (const spec of specs) {
    const row = Object.assign(describe(spec), { identity: key });
    for (const { policy } of policies) {
      const reason = launchRefusal(policy, row, entry);
      if (reason) return reason;
    }
  }
  return null;
}

module.exports = {
  SCHEMA, ENV_VAR, MANAGED_PATHS,
  glob, endpoint, shlexSplit, describe, specFromLock, specFromConfig, parsePolicy,
  launchRefusal, matches, managedPath, forLaunch, refusalFor, safeName, pyStrip, load,
};

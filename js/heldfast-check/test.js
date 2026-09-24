"use strict";

/**
 * The JavaScript half of the cross-language digest contract.
 *
 * `tests/test_digest_parity.py` loads the same vectors and asserts the same
 * strings. Run with `node js/heldfast-check/test.js` or `npm test` from this
 * directory. Zero dependencies, like the module it tests.
 *
 * Before RFC 8785 the two implementations were hand-matched and disagreed on
 * five ordinary inputs, which meant the Claude Code plugin hook reported
 * drift on tools that had been approved correctly. This file exists so that
 * cannot happen again without a test going red.
 */

const assert = require("assert");
const fs = require("fs");
const path = require("path");

const { canonical, toolDigest, LOCK_VERSION } = require("./index.js");

const VECTORS = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "..", "..", "tests", "golden", "jcs_vectors.json"),
    "utf8"));

let run = 0;
let failed = 0;

function check(why, actual, expected) {
  run += 1;
  try {
    assert.strictEqual(actual, expected);
  } catch (err) {
    failed += 1;
    console.error("FAIL  " + why);
    console.error("      expected " + JSON.stringify(expected));
    console.error("      actual   " + JSON.stringify(actual));
  }
}

// -- the shared canonical vectors -------------------------------------------

for (const vector of VECTORS.canonical) {
  check(vector.why, canonical(vector.value), vector.expect);
}

// -- the five divergences, named so a regression says which one -------------

check("an integral float loses its decimal", canonical(1.0), "1");
check("a Pydantic-style bound", canonical({ minimum: 0.0 }), '{"minimum":0}');
check("negative zero folds", canonical(-0.0), canonical(0.0));
check("1e16 is written in full", canonical(1e16), "10000000000000000");
check("key order is UTF-16, not code point",
  canonical({ "": 1, "\u{1f600}": 2 }), '{"\u{1f600}":2,"":1}');

// -- lone surrogates are escaped, never emitted raw -------------------------
//
// Node's JSON.stringify passes a lone surrogate through since the
// well-formed-stringify proposal. That would produce bytes Python's UTF-8
// encoder refuses outright, so this module escapes them explicitly.

check("lone high surrogate", canonical("\ud800"), '"\\ud800"');
check("lone low surrogate", canonical("\udfff"), '"\\udfff"');
check("a surrogate inside a description",
  canonical("hi \ud800 there"), '"hi \\ud800 there"');
check("a well-formed pair is NOT escaped",
  canonical("😀"), '"\u{1f600}"');

// -- digests over whole tool objects ----------------------------------------

for (const vector of VECTORS.digests) {
  run += 1;
  const digest = toolDigest(vector.tool);
  if (!/^[0-9a-f]{64}$/.test(digest)) {
    failed += 1;
    console.error("FAIL  digest is not a sha256 hex: " + vector.why);
  }
}

// -- the lockfile version this checker understands --------------------------

check("lock version is an integer", typeof LOCK_VERSION, "number");

// ---------------------------------------------------------------------------

if (failed) {
  console.error("\n" + failed + " of " + run + " checks failed");
  process.exit(1);
}
console.log(run + " checks passed");

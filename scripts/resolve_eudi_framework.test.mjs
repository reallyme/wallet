// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { authenticateFrameworkCheckout, FrameworkSelectionError, REQUIRED_FRAMEWORK_INPUTS, resolvePublishedFramework } from "./resolve_eudi_framework.mjs";

const commit = "a".repeat(40);
const tag = "v0.3.3";
const digest = "b".repeat(64);
const releaseFixture = () => ({ tag_name: tag, target_commitish: commit, draft: false, prerelease: false,
  html_url: `https://github.com/reallyme/identity-conformance/releases/tag/${tag}`,
  assets: [{ name: "conformance-framework-release.json", size: 123, state: "uploaded",
    content_type: "application/json", digest: `sha256:${digest}` }] });
const run = (reference, mutate = () => {}) => {
  const release = releaseFixture();
  const target = { sha: commit };
  const version = { encoding: "base64", size: 6, content: Buffer.from("0.3.3\n").toString("base64") };
  mutate({ release, target, version });
  const calls = [];
  const selected = resolvePublishedFramework({ reference, query: (endpoint) => {
    calls.push(endpoint);
    if (endpoint.includes("contents/VERSION")) return version;
    if (endpoint.includes("releases/tags/")) return release;
    if (endpoint.includes("commits/")) return target;
    assert.fail("unexpected release endpoint");
  } });
  return { selected, calls };
};

test("explicit published tag and commit resolve to the same immutable release", () => {
  for (const ref of [tag, commit]) {
    assert.deepEqual(run(ref).selected, { commit, tag, manifestSha256: digest });
  }
  assert.ok(run(commit).calls[0].endsWith(`VERSION?ref=${commit}`));
});

test("unbounded, malformed and injectable references are rejected before network I/O", () => {
  for (const reference of [null, {}, undefined, "", "latest", "main", "v01.2.3", "v0.3.3\n", "v0.3.3;true", "A".repeat(40)]) {
    assert.throws(() => run(reference), FrameworkSelectionError);
  }
});

test("dispatch requires a release tag so successful run names always identify a framework version", () => {
  const root = mkdtempSync(join(tmpdir(), "wallet-framework-release-input-"));
  try {
    const output = join(root, "outputs");
    const result = spawnSync(process.execPath,
      [fileURLToPath(new URL("./resolve_eudi_framework.mjs", import.meta.url))], {
        encoding: "utf8", timeout: 10_000,
        env: { ...process.env, GITHUB_REPOSITORY: "reallyme/wallet", GITHUB_REF: "refs/heads/main",
          GITHUB_OUTPUT: output, EUDI_VERIFY_FRAMEWORK: "0", EUDI_FRAMEWORK_REF: tag,
          EUDI_FRAMEWORK_OVERRIDE: commit },
      });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /framework_reference_invalid/u);
    assert.equal(existsSync(output), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

for (const [name, mutate] of [
  ["draft", ({ release }) => { release.draft = true; }],
  ["prerelease", ({ release }) => { release.prerelease = true; }],
  ["different tag", ({ release }) => { release.tag_name = "v0.3.2"; }],
  ["mutable target", ({ release }) => { release.target_commitish = "main"; }],
  ["tag mismatch", ({ target }) => { target.sha = "c".repeat(40); }],
  ["foreign release", ({ release }) => { release.html_url = "https://example.com/release"; }],
  ["missing manifest", ({ release }) => { release.assets = []; }],
  ["duplicate manifest", ({ release }) => { release.assets.push({ ...release.assets[0] }); }],
  ["missing asset digest", ({ release }) => { delete release.assets[0].digest; }],
  ["incomplete asset", ({ release }) => { release.assets[0].state = "new"; }],
  ["unexpected content type", ({ release }) => { release.assets[0].content_type = "text/html"; }],
  ["invalid asset digest", ({ release }) => { release.assets[0].digest = "sha256:bad"; }],
  ["oversized manifest", ({ release }) => { release.assets[0].size = 1_048_577; }],
  ["invalid base64", ({ version }) => { version.content += "!"; }],
  ["wrong version size", ({ version }) => { version.size += 1; }],
  ["branch in VERSION", ({ version }) => { version.content = Buffer.from("main\n").toString("base64"); version.size = 5; }],
]) {
  test(`rejects ${name}`, () => assert.throws(() => run(commit, mutate), FrameworkSelectionError));
}

const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const checkoutFixture = (mutate) => {
  const root = mkdtempSync(join(tmpdir(), "wallet-framework-bootstrap-"));
  try {
    const inputs = [...REQUIRED_FRAMEWORK_INPUTS].sort().map((path) => {
      const bytes = Buffer.from(path === "VERSION" ? "0.3.3\n" : "public test input\n");
      mkdirSync(dirname(join(root, path)), { recursive: true });
      writeFileSync(join(root, path), bytes);
      return { path, sha256: hash(bytes), size: bytes.length };
    });
    const aggregate = (items) => hash(items.map((item) => `${item.path}\0${item.sha256}\0${item.size}\n`).join(""));
    const manifest = { $comment: "public test fixture", schema: "reallyme.identity.conformance_framework_release.v1", release_kind: "framework",
      release_version: "0.3.3", repository_commit: commit, input_set_sha256: aggregate(inputs), inputs };
    const options = { root, manifestPath: join(root, "manifest.json"), commit, tag, manifestSha256: "" };
    mutate?.({ root, manifest, options, aggregate });
    const bytes = Buffer.from(JSON.stringify(manifest));
    writeFileSync(options.manifestPath, bytes);
    options.manifestSha256 ||= hash(bytes);
    return authenticateFrameworkCheckout(options);
  } finally { rmSync(root, { recursive: true, force: true }); }
};

test("Wallet authenticates all manifest inputs before executing selected framework code", () => {
  assert.equal(checkoutFixture().commit, commit);
});

for (const [name, mutate] of [
  ["downloaded asset tampering", ({ options }) => { options.manifestSha256 = "c".repeat(64); }],
  ["manifest commit substitution", ({ manifest }) => { manifest.repository_commit = "c".repeat(40); }],
  ["manifest version substitution", ({ manifest }) => { manifest.release_version = "0.3.2"; }],
  ["unrecognized manifest field", ({ manifest }) => { manifest.unrecognized = true; }],
  ["unrecognized input field", ({ manifest }) => { manifest.inputs[0].unrecognized = true; }],
  ["changed input", ({ root }) => { writeFileSync(join(root, "scripts/strict_json.py"), "tampered\n"); }],
  ["duplicate input", ({ manifest }) => { manifest.inputs.push(manifest.inputs[0]); }],
  ["path traversal", ({ manifest }) => { manifest.inputs[0].path = "../VERSION"; }],
  ["absolute path", ({ manifest }) => { manifest.inputs[0].path = "/VERSION"; }],
  ["noncanonical path", ({ manifest }) => { manifest.inputs[0].path = "./VERSION"; }],
  ["missing bootstrap input", ({ manifest, aggregate }) => { manifest.inputs.pop(); manifest.input_set_sha256 = aggregate(manifest.inputs); }],
  ["aggregate tampering", ({ manifest }) => { manifest.input_set_sha256 = "c".repeat(64); }],
  ["oversized input", ({ manifest }) => { manifest.inputs[0].size = 16_777_217; }],
  ["symlink input", ({ root }) => { rmSync(join(root, "VERSION")); symlinkSync("scripts/strict_json.py", join(root, "VERSION")); }],
  ["symlink directory", ({ root }) => { rmSync(join(root, "scripts"), { recursive: true }); symlinkSync(".", join(root, "scripts")); }],
]) {
  test(`bootstrap rejects ${name}`, () => assert.throws(() => checkoutFixture(mutate), FrameworkSelectionError));
}

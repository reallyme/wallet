#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { appendFileSync, lstatSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPOSITORY = "reallyme/identity-conformance";
const COMMIT = /^[0-9a-f]{40}$/u;
const RELEASE_TAG = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const MAX_RESPONSE_BYTES = 1_048_576;
const MAX_VERSION_BYTES = 64;
const MAX_INPUT_BYTES = 16_777_216;
const MAX_INPUTS = 4096;
const MAX_TOTAL_INPUT_BYTES = 134_217_728;
const DIGEST = /^[0-9a-f]{64}$/u;
const COMMAND_TIMEOUT_MS = 120_000;
export const REQUIRED_FRAMEWORK_INPUTS = Object.freeze(["VERSION", "scripts/prepare_published_framework_release.sh",
  "scripts/verify_published_framework_release.py", "scripts/build_release_manifest.py", "scripts/strict_json.py",
  "scripts/verify_eudi_wallet_deployment_manifest.py", "scripts/verify_component_attestation.py",
  "scripts/run_eudi_wallet_conformance.py", "scripts/verify_eudi_wallet_execution_result.py",
  "scripts/verify_wallet_package_preflight.py", "scripts/materialize_wallet_attestation_subjects.py",
  "scripts/verify_wallet_published_target.py", "scripts/build_wallet_conformance_statement.py"]);
const record = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const exactKeys = (value, keys) => record(value) &&
  Object.keys(value).sort().join("\n") === [...keys].sort().join("\n");

export class FrameworkSelectionError extends Error {
  constructor(code) {
    super(code);
    this.name = "FrameworkSelectionError";
    this.code = code;
  }
}
const fail = (code) => { throw new FrameworkSelectionError(code); };

const queryGithub = (endpoint) => {
  const result = spawnSync("gh", ["api", endpoint], {
    encoding: "utf8", timeout: COMMAND_TIMEOUT_MS, maxBuffer: MAX_RESPONSE_BYTES,
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (result.error !== undefined || result.status !== 0) fail("framework_query_failed");
  try { return JSON.parse(result.stdout); } catch { fail("framework_response_invalid"); }
};

/** Resolve an explicit published release before any selected framework code runs. */
export const resolvePublishedFramework = ({ reference, query = queryGithub }) => {
  if (typeof reference !== "string" || (!COMMIT.test(reference) && !RELEASE_TAG.test(reference))) {
    fail("framework_reference_invalid");
  }
  let tag = reference;
  if (COMMIT.test(reference)) {
    const source = query(`repos/${REPOSITORY}/contents/VERSION?ref=${reference}`);
    if (!record(source) || source.encoding !== "base64" || typeof source.content !== "string" ||
        !Number.isSafeInteger(source.size) || source.size < 1 || source.size > MAX_VERSION_BYTES ||
        source.content.length > MAX_VERSION_BYTES * 2) fail("framework_version_invalid");
    const encoded = source.content.replaceAll("\n", "");
    const bytes = Buffer.from(encoded, "base64");
    if (bytes.length !== source.size || bytes.toString("base64") !== encoded) fail("framework_version_invalid");
    const version = bytes.toString("utf8").replace(/\n$/u, "");
    tag = `v${version}`;
    if (!RELEASE_TAG.test(tag)) fail("framework_version_invalid");
  }
  const release = query(`repos/${REPOSITORY}/releases/tags/${tag}`);
  const target = query(`repos/${REPOSITORY}/commits/${tag}`);
  if (!record(release) || !record(target) || typeof target.sha !== "string" || !COMMIT.test(target.sha) ||
      release.tag_name !== tag || release.target_commitish !== target.sha ||
      release.draft !== false || release.prerelease !== false ||
      release.html_url !== `https://github.com/${REPOSITORY}/releases/tag/${tag}` ||
      (COMMIT.test(reference) && reference !== target.sha)) fail("framework_release_mismatch");
  if (!Array.isArray(release.assets) || release.assets.length > 128) fail("framework_manifest_unavailable");
  const assets = release.assets.filter((asset) => record(asset) && asset.name === "conformance-framework-release.json");
  if (assets.length !== 1 || !Number.isSafeInteger(assets[0].size) || assets[0].size < 1 ||
      assets[0].size > MAX_RESPONSE_BYTES || typeof assets[0].digest !== "string" ||
      assets[0].state !== "uploaded" || assets[0].content_type !== "application/json" ||
      !/^sha256:[0-9a-f]{64}$/u.test(assets[0].digest)) {
    fail("framework_manifest_unavailable");
  }
  // The selected framework's existing verifier subsequently rebuilds and checks
  // the complete release manifest against this exact checkout, not just the tag.
  return Object.freeze({ commit: target.sha, tag, manifestSha256: assets[0].digest.slice(7) });
};

const fileStatus = (path) => {
  let status;
  try { status = lstatSync(path); } catch { fail("framework_file_invalid"); }
  return status;
};
const regularBytes = (path, maximum) => {
  const status = fileStatus(path);
  if (!status.isFile() || status.isSymbolicLink() || status.size < 1 || status.size > maximum) {
    fail("framework_file_invalid");
  }
  try { return readFileSync(path); } catch { fail("framework_file_invalid"); }
};
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** Authenticate published bytes independently before running framework Python. */
export const authenticateFrameworkCheckout = ({ root, manifestPath, commit, tag, manifestSha256 }) => {
  if (!COMMIT.test(commit ?? "") || !RELEASE_TAG.test(tag ?? "") || !DIGEST.test(manifestSha256 ?? "")) {
    fail("framework_reference_invalid");
  }
  const bytes = regularBytes(manifestPath, MAX_RESPONSE_BYTES);
  if (hash(bytes) !== manifestSha256) fail("framework_manifest_digest_mismatch");
  let manifest;
  try { manifest = JSON.parse(bytes.toString("utf8")); } catch { fail("framework_manifest_invalid"); }
  if (!exactKeys(manifest, ["$comment", "schema", "release_kind", "release_version", "repository_commit", "input_set_sha256", "inputs"]) ||
      typeof manifest.$comment !== "string" || manifest.schema !== "reallyme.identity.conformance_framework_release.v1" ||
      manifest.release_kind !== "framework" || manifest.release_version !== tag.slice(1) ||
      manifest.repository_commit !== commit || !DIGEST.test(manifest.input_set_sha256 ?? "") ||
      !Array.isArray(manifest.inputs) || manifest.inputs.length < 1 || manifest.inputs.length > MAX_INPUTS) {
    fail("framework_manifest_invalid");
  }
  const base = resolve(root);
  const rootStatus = fileStatus(base);
  if (rootStatus.isSymbolicLink() || !rootStatus.isDirectory()) fail("framework_file_invalid");
  const aggregate = createHash("sha256");
  let previous = "";
  let totalInputBytes = 0;
  const required = new Set(REQUIRED_FRAMEWORK_INPUTS);
  for (const input of manifest.inputs) {
    if (!exactKeys(input, ["path", "sha256", "size"]) || typeof input.path !== "string" || input.path.length > 512 ||
        !/^[A-Za-z0-9_./-]+$/u.test(input.path) || input.path.split("/").some((part) => ["", ".", ".."].includes(part)) ||
        input.path <= previous || !DIGEST.test(input.sha256 ?? "") ||
        !Number.isSafeInteger(input.size) || input.size < 1 || input.size > MAX_INPUT_BYTES) {
      fail("framework_manifest_invalid");
    }
    let path = base;
    for (const part of input.path.split("/")) {
      path = join(path, part);
      if (fileStatus(path).isSymbolicLink()) fail("framework_file_invalid");
    }
    totalInputBytes += input.size;
    if (!Number.isSafeInteger(totalInputBytes) || totalInputBytes > MAX_TOTAL_INPUT_BYTES) fail("framework_manifest_invalid");
    const content = regularBytes(path, MAX_INPUT_BYTES);
    if (content.length !== input.size || hash(content) !== input.sha256) fail("framework_input_mismatch");
    aggregate.update(`${input.path}\0${input.sha256}\0${input.size}\n`);
    previous = input.path;
    required.delete(input.path);
  }
  if (required.size !== 0 || aggregate.digest("hex") !== manifest.input_set_sha256 ||
      regularBytes(join(base, "VERSION"), MAX_VERSION_BYTES).toString("utf8").replace(/\n$/u, "") !== tag.slice(1)) {
    fail("framework_input_mismatch");
  }
  return Object.freeze({ commit, tag, manifestSha256, inputSetSha256: manifest.input_set_sha256 });
};

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    if (process.env.GITHUB_REPOSITORY !== "reallyme/wallet" || process.env.GITHUB_REF !== "refs/heads/main" ||
        typeof process.env.GITHUB_OUTPUT !== "string" || process.env.GITHUB_OUTPUT.length === 0) {
      fail("framework_dispatch_invalid");
    }
    if (process.env.EUDI_VERIFY_FRAMEWORK === "1") {
      authenticateFrameworkCheckout({ root: process.env.EUDI_FRAMEWORK_PATH,
        manifestPath: process.env.EUDI_FRAMEWORK_MANIFEST, commit: process.env.FRAMEWORK_COMMIT,
        tag: process.env.FRAMEWORK_TAG, manifestSha256: process.env.FRAMEWORK_MANIFEST_SHA256 });
    } else {
      const selected = resolvePublishedFramework({ reference: process.env.EUDI_FRAMEWORK_OVERRIDE || process.env.EUDI_FRAMEWORK_REF });
      appendFileSync(process.env.GITHUB_OUTPUT,
        `commit=${selected.commit}\ntag=${selected.tag}\nmanifest_sha256=${selected.manifestSha256}\n`, "utf8");
    }
  } catch (error) {
    const code = error instanceof FrameworkSelectionError ? error.code : "framework_selection_failed";
    console.error(`EUDI framework selection failed: ${code}`);
    process.exitCode = 1;
  }
}

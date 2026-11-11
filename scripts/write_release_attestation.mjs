#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const FULL_SHA_PATTERN = /^[0-9a-f]{40}$/u;
const POSITIVE_INTEGER_PATTERN = /^[1-9][0-9]*$/u;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const OUTPUT_DIRECTORY = "release-attestation";
const OUTPUT_PATH = `${OUTPUT_DIRECTORY}/crates-preflight.json`;
const PACKAGE_DIRECTORY = "target/package";
const POLICY_PATH = fileURLToPath(new URL("../conformance/features/wallet-package-policy-v1.json", import.meta.url));
const PREREQUISITE_RUNS = Object.freeze({
  fuzz: "FUZZ_RUN_ID",
  protobuf_ci: "PROTOBUF_CI_RUN_ID",
  rust_ci: "RUST_CI_RUN_ID",
});

const fail = (code) => {
  console.error(`release attestation creation failed: ${code}`);
  process.exit(1);
};

const parsePositiveInteger = (value, code) => {
  if (typeof value !== "string" || !POSITIVE_INTEGER_PATTERN.test(value)) fail(code);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) fail(code);
  return parsed;
};

let policy;
try {
  policy = JSON.parse(readFileSync(POLICY_PATH, "utf8"));
} catch {
  fail("invalid-release-policy");
}
const expectedPackages = new Set(policy.authorized_public_packages);
if (expectedPackages.size !== policy.authorized_public_packages.length) {
  fail("duplicate-release-policy-package");
}

const repository = process.env.GITHUB_REPOSITORY;
const releaseSha = process.env.RELEASE_SHA;
const version = process.env.RELEASE_VERSION;
if (typeof repository !== "string" || !REPOSITORY_PATTERN.test(repository)) fail("invalid-repository");
if (typeof releaseSha !== "string" || !FULL_SHA_PATTERN.test(releaseSha)) fail("invalid-release-sha");
if (typeof version !== "string" || !VERSION_PATTERN.test(version)) fail("invalid-release-version");
if (version !== policy.release_version) fail("release-version-policy-mismatch");
const runId = parsePositiveInteger(process.env.GITHUB_RUN_ID, "invalid-run-id");
const runAttempt = parsePositiveInteger(process.env.GITHUB_RUN_ATTEMPT, "invalid-run-attempt");
if (runAttempt !== 1) fail("rerun-cannot-create-release-attestation");

let archiveNames;
try {
  archiveNames = readdirSync(PACKAGE_DIRECTORY)
    .filter((name) => name.endsWith(`-${version}.crate`))
    .sort();
} catch {
  fail("package-archives-missing");
}
if (archiveNames.length !== expectedPackages.size) fail("package-archive-count-mismatch");

const crates = archiveNames.map((file) => {
  const suffix = `-${version}.crate`;
  const name = file.slice(0, -suffix.length);
  const path = resolve(PACKAGE_DIRECTORY, file);
  if (!expectedPackages.has(name)) fail("package-archive-set-mismatch");
  try {
    const status = statSync(path);
    if (!status.isFile() || status.size < 1) fail("invalid-package-archive");
    return {
      file,
      sha256: createHash("sha256").update(readFileSync(path)).digest("hex"),
      size: status.size,
    };
  } catch {
    fail("invalid-package-archive");
  }
});

const attestation = {
  schema: "reallyme.wallet.crates_preflight.v3",
  crates,
  prerequisites: Object.fromEntries(
    Object.entries(PREREQUISITE_RUNS).map(([name, environmentName]) => [
      name,
      parsePositiveInteger(process.env[environmentName], `invalid-${name}-run-id`),
    ]),
  ),
  repository,
  workflow: "crates-package-preflight.yml",
  run_id: runId,
  run_attempt: runAttempt,
  release_sha: releaseSha,
  version,
};

try {
  mkdirSync(OUTPUT_DIRECTORY, { recursive: true });
  writeFileSync(OUTPUT_PATH, `${JSON.stringify(attestation, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
} catch {
  fail("attestation-write-failed");
}
console.log("reviewed crates package attestation written");

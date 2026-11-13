#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  ReleaseAttestationError,
  selectLatestPreflightRun,
  verifyAttestedCrateArchives,
  verifyAttestationDocument,
  verifyWorkflowRun,
  verifyReleaseAttestation,
} from "./verify_release_attestation.mjs";

const releaseSha = "a".repeat(40);
const policy = JSON.parse(readFileSync(new URL("../conformance/features/wallet-package-policy-v1.json", import.meta.url), "utf8"));
const crateFiles = [...policy.authorized_public_packages]
  .map((name) => `${name}-${policy.release_version}.crate`)
  .sort();
const expected = Object.freeze({
  repository: "reallyme/wallet",
  runId: 123,
  releaseSha,
  releaseVersion: policy.release_version,
});
const attestation = (overrides = {}) => ({
  schema: "reallyme.wallet.crates_preflight.v3",
  repository: expected.repository,
  workflow: "crates-package-preflight.yml",
  run_id: expected.runId,
  run_attempt: 1,
  release_sha: releaseSha,
  version: expected.releaseVersion,
  crates: crateFiles.map((file) => ({
    file,
    sha256: "a".repeat(64),
    size: 1,
  })),
  prerequisites: { fuzz: 11, protobuf_ci: 12, rust_ci: 13 },
  ...overrides,
});
const workflowRun = (overrides = {}) => ({
  workflow_id: 456,
  id: expected.runId,
  event: "workflow_dispatch",
  head_branch: "main",
  head_sha: releaseSha,
  status: "completed",
  conclusion: "success",
  run_attempt: 1,
  path: ".github/workflows/crates-package-preflight.yml",
  ...overrides,
});
const listedWorkflowRun = (overrides = {}) => ({
  workflow_id: 456,
  id: expected.runId,
  event: "workflow_dispatch",
  head_branch: "main",
  head_sha: releaseSha,
  status: "completed",
  conclusion: "success",
  run_attempt: 1,
  path: ".github/workflows/crates-package-preflight.yml",
  display_title: `Crates package preflight ${expected.releaseVersion} @ ${releaseSha}`,
  ...overrides,
});

test("reviewed attestation accepts the exact run, SHA, and version", () => {
  assert.doesNotThrow(() => verifyAttestationDocument(attestation(), expected));
  assert.doesNotThrow(() =>
    verifyWorkflowRun(workflowRun(), {
      workflowId: 456,
      runId: expected.runId,
      releaseSha,
    }),
  );
});

test("attestation rejects mismatched inputs and unreviewed fields", () => {
  for (const candidate of [
    attestation({ version: "0.2.1" }),
    attestation({ release_sha: "b".repeat(40) }),
    attestation({ run_id: 124 }),
    attestation({ extra: true }),
  ]) {
    assert.throws(
      () => verifyAttestationDocument(candidate, expected),
      ReleaseAttestationError,
    );
  }
});

test("attestation rejects missing or substituted approved crate evidence", () => {
  for (const crates of [
    attestation().crates.slice(1),
    [...attestation().crates.slice(1), {
      file: `unapproved-package-${expected.releaseVersion}.crate`,
      sha256: "a".repeat(64),
      size: 1,
    }].sort((left, right) => left.file.localeCompare(right.file)),
  ]) {
    assert.throws(
      () => verifyAttestationDocument(attestation({ crates }), expected),
      ReleaseAttestationError,
    );
  }
});

test("historical package policy is explicit and remains strictly validated", () => {
  const releaseVersion = "0.1.1";
  const packageNames = policy.authorized_public_packages.slice(0, 2).sort();
  const historical = attestation({
    version: releaseVersion,
    crates: packageNames.map((name) => ({
      file: `${name}-${releaseVersion}.crate`, sha256: "b".repeat(64), size: 1,
    })),
  });
  const historicalExpected = { ...expected, releaseVersion, packageNames };
  assert.doesNotThrow(() => verifyAttestationDocument(historical, historicalExpected));
  for (const invalid of [[], [packageNames[0], packageNames[0]], ["foreign-package"]]) {
    assert.throws(
      () => verifyAttestationDocument(historical, { ...historicalExpected, packageNames: invalid }),
      ReleaseAttestationError,
    );
  }
});

test("reviewed crate bytes must match both size and digest", () => {
  const directory = mkdtempSync(join(tmpdir(), "wallet-attestation-"));
  try {
    const file = crateFiles[0];
    const bytes = Buffer.from("reviewed archive", "utf8");
    writeFileSync(join(directory, file), bytes);
    const reviewed = {
      crates: [{
        file,
        sha256: createHash("sha256").update(bytes).digest("hex"),
        size: bytes.length,
      }],
    };
    assert.doesNotThrow(() => verifyAttestedCrateArchives(reviewed, directory));
    writeFileSync(join(directory, file), Buffer.from("substituted", "utf8"));
    assert.throws(
      () => verifyAttestedCrateArchives(reviewed, directory),
      ReleaseAttestationError,
    );
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});

test("failed, rerun, wrong-branch, and wrong-workflow runs fail closed", () => {
  for (const candidate of [
    workflowRun({ conclusion: "failure" }),
    workflowRun({ run_attempt: 2 }),
    workflowRun({ head_branch: "feature" }),
    workflowRun({ workflow_id: 457 }),
    workflowRun({ path: ".github/workflows/other.yml@refs/heads/main" }),
  ]) {
    assert.throws(
      () =>
        verifyWorkflowRun(candidate, {
          workflowId: 456,
          runId: expected.runId,
          releaseSha,
        }),
      ReleaseAttestationError,
    );
  }
});

test("automatic resolution selects the latest exact successful preflight", () => {
  const latest = selectLatestPreflightRun(
    {
      workflow_runs: [
        listedWorkflowRun({ id: 121 }),
        listedWorkflowRun({ id: 123 }),
        listedWorkflowRun({ id: 124, head_sha: "b".repeat(40) }),
      ],
    },
    {
      workflowId: 456,
      releaseSha,
      releaseVersion: expected.releaseVersion,
    },
  );
  assert.equal(latest.id, 123);
});

test("newer failed, running, wrong-version, and rerun preflights fail closed", () => {
  const rejectedLatestRuns = [
    listedWorkflowRun({ id: 124, conclusion: "failure" }),
    listedWorkflowRun({ id: 124, conclusion: null, status: "in_progress" }),
    listedWorkflowRun({
      id: 124,
      display_title: `Crates package preflight 0.2.1 @ ${releaseSha}`,
    }),
    listedWorkflowRun({ id: 124, run_attempt: 2 }),
  ];
  for (const rejected of rejectedLatestRuns) {
    assert.throws(
      () =>
        selectLatestPreflightRun(
          { workflow_runs: [listedWorkflowRun({ id: 123 }), rejected] },
          {
            workflowId: 456,
            releaseSha,
            releaseVersion: expected.releaseVersion,
          },
        ),
      ReleaseAttestationError,
    );
  }
});

test("automatic resolution rejects missing and malformed workflow results", () => {
  for (const candidate of [{}, { workflow_runs: [] }, { workflow_runs: [null] }]) {
    assert.throws(
      () =>
        selectLatestPreflightRun(candidate, {
          workflowId: 456,
          releaseSha,
          releaseVersion: expected.releaseVersion,
        }),
      ReleaseAttestationError,
    );
  }
});

test("waiting rejects zero polling intervals before querying GitHub", () => {
  assert.throws(() => verifyReleaseAttestation({ env: {
    GITHUB_REPOSITORY: expected.repository,
    RELEASE_SHA: releaseSha,
    RELEASE_VERSION: expected.releaseVersion,
    GITHUB_SHA: releaseSha,
    GH_TOKEN: "test-placeholder",
    RELEASE_ATTESTATION_WAIT_SECONDS: "60",
    RELEASE_ATTESTATION_POLL_SECONDS: "0",
  } }), { name: "ReleaseAttestationError", code: "invalid-release-attestation-poll-seconds" });
});

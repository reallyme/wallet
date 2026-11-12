// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  buildEudiDeploymentInputs, derivePreflightChecks, EudiReleaseEvidenceError,
  sha256, verifyPublishedRelease, verifyRegistryVersion,
} from "./eudi_release_evidence.mjs";

const identity = { runId: 42, releaseSha: "a".repeat(40) };
const stepNames = ["Check formatting", "Clippy", "Test all features",
  "Check protobuf boundaries and generated source", "Check dependency policy",
  "Security advisory audit", "Inspect normalized crate tarballs and dry-run publication",
  "Check Identity Wasm participant lane"];
const jobs = () => ({ total_count: 1, jobs: [{
  id: 7, run_id: 42, run_attempt: 1, head_sha: identity.releaseSha,
  name: "Review crates.io packages", status: "completed", conclusion: "success",
  steps: stepNames.map((name, index) => ({ name, number: index + 1, status: "completed", conclusion: "success" })),
}] });

test("only actual successful steps become component check claims and reproducible evidence", () => {
  const result = derivePreflightChecks(jobs(), identity);
  assert.equal(result.checks.length, 7);
  assert.equal(result.evidence.length, 7);
  for (const check of result.checks) {
    const evidence = result.evidence.find((item) => item.file === `evidence-${check.category}.json`);
    assert.ok(evidence);
    assert.equal(check.evidence_sha256, createHash("sha256").update(evidence.bytes).digest("hex"));
    const record = JSON.parse(evidence.bytes);
    assert.equal(record.run_id, identity.runId);
    assert.equal(record.release_sha, identity.releaseSha);
    assert.ok(record.steps.every((step) => step.conclusion === "success"));
  }
});

for (const state of ["failure", "skipped", "cancelled", "neutral", null]) {
  test(`a ${state} required step cannot be relabelled as passing`, () => {
    const changed = jobs();
    changed.jobs[0].steps[0].conclusion = state;
    assert.throws(() => derivePreflightChecks(changed, identity), EudiReleaseEvidenceError);
  });
}

for (const field of ["run_id", "run_attempt", "head_sha", "status", "conclusion", "id"]) {
  test(`mismatched or incomplete job ${field} is rejected`, () => {
    const changed = jobs();
    changed.jobs[0][field] = field === "head_sha" ? "b".repeat(40) : field.includes("run_") ? 2 : null;
    assert.throws(() => derivePreflightChecks(changed, identity), EudiReleaseEvidenceError);
  });
}

test("missing, duplicate, partial and oversized job/step sets fail closed", () => {
  const variants = [];
  const missing = jobs(); missing.jobs[0].steps.shift(); variants.push(missing);
  const duplicateStep = jobs(); duplicateStep.jobs[0].steps.push(duplicateStep.jobs[0].steps[0]); variants.push(duplicateStep);
  const duplicateJob = jobs(); duplicateJob.jobs.push(duplicateJob.jobs[0]); duplicateJob.total_count = 2; variants.push(duplicateJob);
  const paginated = jobs(); paginated.total_count = 101; variants.push(paginated);
  const tooMany = jobs(); tooMany.jobs[0].steps = Array(101).fill({}); variants.push(tooMany);
  for (const value of [null, {}, { total_count: 0, jobs: [] }, ...variants]) {
    assert.throws(() => derivePreflightChecks(value, identity), EudiReleaseEvidenceError);
  }
});

test("draft, prerelease, substituted and malformed GitHub releases are rejected", () => {
  const value = { id: 1, tag_name: "reallyme-wallet-v0.1.0", draft: false, prerelease: false };
  verifyPublishedRelease(value, value.tag_name);
  for (const mutation of [{ draft: true }, { prerelease: true }, { tag_name: "other" }, { id: 0 }]) {
    assert.throws(() => verifyPublishedRelease({ ...value, ...mutation }, value.tag_name), EudiReleaseEvidenceError);
  }
});

test("registry name, version, checksum and non-yanked state must all match", () => {
  const checksum = "c".repeat(64);
  const version = { crate: "reallyme-wallet", num: "0.1.0", checksum, yanked: false };
  verifyRegistryVersion({ version }, version.crate, version.num, checksum);
  for (const mutation of [{ crate: "other" }, { num: "0.1.1" }, { checksum: "d".repeat(64) }, { yanked: true }]) {
    assert.throws(() => verifyRegistryVersion({ version: { ...version, ...mutation } }, version.crate, version.num, checksum), EudiReleaseEvidenceError);
  }
});

const material = () => ({
  version: "0.1.0", releaseSha: identity.releaseSha, bundleHash: "b".repeat(64), cargoLockHash: "c".repeat(64),
  sourceLocks: { eudi_sources_sha256: "d".repeat(64), eudi_legal_sources_sha256: "e".repeat(64), eudi_publications_sha256: "f".repeat(64) },
  checks: derivePreflightChecks(jobs(), identity).checks, createdAt: "2026-11-12T00:00:00.000Z",
});

test("manifest and component attestation bind the same exact candidate and bytes", () => {
  const input = material();
  const { attestationBytes, deploymentBytes } = buildEudiDeploymentInputs(input);
  const attestation = JSON.parse(attestationBytes);
  const deployment = JSON.parse(deploymentBytes);
  assert.equal(deployment.component_attestation_sha256, sha256(attestationBytes));
  assert.equal(deployment.component.commit, attestation.component.source_commit);
  assert.equal(deployment.release_artifact.sha256, attestation.artifacts[0].sha256);
  assert.equal(attestation.release.source_ref, "reallyme-wallet-v0.1.0");
  assert.deepEqual(attestation.checks, input.checks);
  assert.deepEqual(deployment.source_locks, input.sourceLocks);
});

test("missing, duplicated, failed or invented check categories cannot form an attestation", () => {
  for (const mutate of [
    (checks) => checks.pop(),
    (checks) => { checks[1] = checks[0]; },
    (checks) => { checks[0].result = "failed"; },
    (checks) => { checks[0].category = "invented"; },
    (checks) => { checks[0].evidence_sha256 = "bad"; },
  ]) {
    const input = material(); mutate(input.checks);
    assert.throws(() => buildEudiDeploymentInputs(input), EudiReleaseEvidenceError);
  }
});

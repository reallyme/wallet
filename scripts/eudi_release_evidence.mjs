// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";

const FULL_SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_JOB_COUNT = 100;
const MAX_STEP_COUNT = 100;
const REQUIRED_STEPS = Object.freeze({
  format: ["Check formatting"],
  lint: ["Clippy"],
  unit: ["Test all features"],
  integration: ["Test all features"],
  vector: ["Check protobuf boundaries and generated source", "Test all features"],
  security: ["Check dependency policy", "Security advisory audit"],
  build: ["Inspect normalized crate tarballs and dry-run publication", "Check Identity Wasm participant lane"],
});

export class EudiReleaseEvidenceError extends Error {
  constructor(code) {
    super(code);
    this.name = "EudiReleaseEvidenceError";
    this.code = code;
  }
}

export const failEudiEvidence = (code) => { throw new EudiReleaseEvidenceError(code); };
export const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const positiveInteger = (value) => Number.isSafeInteger(value) && value > 0;

export const verifyPublishedRelease = (release, tag) => {
  if (!isRecord(release) || release.tag_name !== tag || release.draft !== false ||
      release.prerelease !== false || !positiveInteger(release.id)) {
    failEudiEvidence("invalid_published_release");
  }
};

export const verifyRegistryVersion = (value, name, version, expectedHash) => {
  const published = isRecord(value) ? value.version : undefined;
  if (!isRecord(published) || published.crate !== name || published.num !== version ||
      published.yanked !== false || published.checksum !== expectedHash || !SHA256.test(expectedHash)) {
    failEudiEvidence("published_registry_mismatch");
  }
};

/** Derive claims only from named, successful steps in the exact signed preflight run. */
export const derivePreflightChecks = (value, { runId, releaseSha }) => {
  if (!positiveInteger(runId) || !FULL_SHA.test(releaseSha) || !isRecord(value) ||
      !Array.isArray(value.jobs) || value.jobs.length > MAX_JOB_COUNT ||
      value.total_count !== value.jobs.length) failEudiEvidence("invalid_preflight_jobs");
  const matches = value.jobs.filter((job) => isRecord(job) && job.name === "Review crates.io packages");
  if (matches.length !== 1) failEudiEvidence("invalid_preflight_jobs");
  const job = matches[0];
  if (!positiveInteger(job.id) || job.run_id !== runId || job.run_attempt !== 1 ||
      job.head_sha !== releaseSha || job.status !== "completed" || job.conclusion !== "success" ||
      !Array.isArray(job.steps) || job.steps.length > MAX_STEP_COUNT) {
    failEudiEvidence("invalid_preflight_jobs");
  }
  const evidence = [];
  const checks = Object.entries(REQUIRED_STEPS).map(([category, names]) => {
    const steps = names.map((name) => {
      const matching = job.steps.filter((step) => isRecord(step) && step.name === name);
      if (matching.length !== 1 || matching[0].status !== "completed" ||
          matching[0].conclusion !== "success" || !positiveInteger(matching[0].number)) {
        failEudiEvidence("required_preflight_step_not_passed");
      }
      return { name, number: matching[0].number, status: "completed", conclusion: "success" };
    });
    const record = {
      schema: "reallyme.wallet.eudi_release_check_evidence.v1",
      repository: "reallyme/wallet", release_sha: releaseSha,
      run_id: runId, run_attempt: 1, job_id: job.id, category, steps,
    };
    const bytes = `${JSON.stringify(record, null, 2)}\n`;
    evidence.push({ file: `evidence-${category}.json`, bytes });
    return {
      check_id: `release-preflight-${category}`, category,
      result: "passed", evidence_sha256: sha256(bytes),
    };
  });
  return { checks, evidence };
};

export const buildEudiDeploymentInputs = ({
  version, releaseSha, bundleHash, cargoLockHash, sourceLocks, checks, createdAt,
}) => {
  if (!/^\d+\.\d+\.\d+$/u.test(version) || !FULL_SHA.test(releaseSha) ||
      !SHA256.test(bundleHash) || !SHA256.test(cargoLockHash) || !isRecord(sourceLocks) ||
      Object.keys(sourceLocks).sort().join(",") !==
        "eudi_legal_sources_sha256,eudi_publications_sha256,eudi_sources_sha256" ||
      Object.values(sourceLocks).some((value) => typeof value !== "string" || !SHA256.test(value)) ||
      !Array.isArray(checks) || checks.length !== Object.keys(REQUIRED_STEPS).length ||
      typeof createdAt !== "string" || !Number.isFinite(Date.parse(createdAt))) {
    failEudiEvidence("invalid_deployment_material");
  }
  const categories = new Set();
  for (const check of checks) {
    if (!isRecord(check) || !Object.hasOwn(REQUIRED_STEPS, check.category) ||
        check.check_id !== `release-preflight-${check.category}` || check.result !== "passed" ||
        typeof check.evidence_sha256 !== "string" || !SHA256.test(check.evidence_sha256) ||
        categories.has(check.category)) failEudiEvidence("invalid_deployment_material");
    categories.add(check.category);
  }
  const attestation = {
    schema: "reallyme.identity.component_attestation.v1", classification: "internal",
    component: { component_id: "wallet", repository: "https://github.com/reallyme/wallet", source_commit: releaseSha },
    release: { version, source_ref: `reallyme-wallet-v${version}` },
    artifacts: [{ artifact_id: "wallet-release-bundle", kind: "archive", sha256: bundleHash }],
    dependency_lock: { kind: "cargo", sha256: cargoLockHash },
    // This identifies the release-preflight toolchain, not the framework runner.
    toolchain: { identifier: "rust", version: "1.99.0" },
    checks, created_at: createdAt,
    evidence_policy: {
      contains_sensitive_data: false, raw_process_output_retained: false,
      credentials_retained: false, private_key_material_retained: false,
    },
  };
  const attestationBytes = `${JSON.stringify(attestation, null, 2)}\n`;
  const deployment = {
    schema: "reallyme.identity.eudi_wallet_deployment_manifest.v1", plan_id: "eudi-wallet-engineering-v1",
    component: { component_id: "wallet", repository: "https://github.com/reallyme/wallet", commit: releaseSha },
    release_artifact: { artifact_id: "wallet-release-bundle", kind: "archive", sha256: bundleHash },
    component_attestation_sha256: sha256(attestationBytes), source_locks: sourceLocks,
    evidence_policy: {
      contains_sensitive_data: false, raw_process_output_retained: false,
      credential_payloads_retained: false, private_key_material_retained: false,
    },
  };
  return { attestationBytes, deploymentBytes: `${JSON.stringify(deployment, null, 2)}\n` };
};

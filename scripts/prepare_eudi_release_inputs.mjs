#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyAttestationDocument, verifyAttestedCrateArchives, verifyWorkflowRun } from "./verify_release_attestation.mjs";
import { verifyReleaseTag } from "./verify_release_tag.mjs";
import {
  buildEudiDeploymentInputs, derivePreflightChecks, EudiReleaseEvidenceError,
  failEudiEvidence, isRecord, sha256, verifyPublishedRelease, verifyRegistryVersion,
} from "./eudi_release_evidence.mjs";

const REPOSITORY = "reallyme/wallet";
const MAX_COMMAND_BYTES = 2_097_152;
const MAX_JSON_BYTES = 1_048_576;
const MAX_ARCHIVE_BYTES = 16_777_216;
const COMMAND_TIMEOUT_MS = 120_000;
const FULL_SHA = /^[0-9a-f]{40}$/u;
const POLICY = JSON.parse(readFileSync(new URL("../conformance/features/wallet-package-policy-v1.json", import.meta.url), "utf8"));

const command = (program, args) => {
  const result = spawnSync(program, args, {
    encoding: "utf8", maxBuffer: MAX_COMMAND_BYTES, timeout: COMMAND_TIMEOUT_MS,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error !== undefined || result.status !== 0) failEudiEvidence("release_evidence_command_failed");
  return result.stdout;
};
const decodeJson = (text) => {
  try { return JSON.parse(text); } catch { failEudiEvidence("invalid_release_json"); }
};
const github = (endpoint) => decodeJson(command("gh", ["api", endpoint]));
const regularBytes = (path, maximum) => {
  let status;
  try { status = lstatSync(path); } catch { failEudiEvidence("release_file_unavailable"); }
  if (status.isSymbolicLink() || !status.isFile() || status.size < 1 || status.size > maximum) {
    failEudiEvidence("invalid_release_file");
  }
  return readFileSync(path);
};

/** Materialize caller inputs from public, signed release evidence only. */
export const prepareEudiReleaseInputs = async ({ env = process.env } = {}) => {
  const frameworkCommit = env.FRAMEWORK_COMMIT;
  if (env.GITHUB_REPOSITORY !== REPOSITORY || typeof env.GH_TOKEN !== "string" || env.GH_TOKEN.length === 0 ||
      !FULL_SHA.test(frameworkCommit ?? "") || typeof env.RUNNER_TEMP !== "string" ||
      typeof env.EUDI_FRAMEWORK_PATH !== "string" || typeof env.EUDI_INPUT_DIRECTORY !== "string") {
    failEudiEvidence("invalid_eudi_runner_environment");
  }
  const framework = resolve(env.EUDI_FRAMEWORK_PATH);
  if (command("git", ["-C", framework, "rev-parse", "HEAD"]).trim() !== frameworkCommit ||
      command("git", ["-C", framework, "status", "--porcelain"]).trim() !== "") {
    failEudiEvidence("framework_checkout_mismatch");
  }
  const output = resolve(env.EUDI_INPUT_DIRECTORY);
  const scratch = mkdtempSync(join(resolve(env.RUNNER_TEMP), "wallet-public-release-"));
  const version = POLICY.release_version;
  const tag = `reallyme-wallet-v${version}`;
  try {
    const release = github(`repos/${REPOSITORY}/releases/tags/${tag}`);
    verifyPublishedRelease(release, tag);
    command("gh", ["release", "download", tag, "--repo", REPOSITORY,
      "--dir", scratch, "--pattern", "crates-preflight.json", "--pattern", "*.crate"]);
    const manifestPath = join(scratch, "crates-preflight.json");
    const manifest = decodeJson(regularBytes(manifestPath, MAX_JSON_BYTES).toString("utf8"));
    if (!isRecord(manifest) || !FULL_SHA.test(manifest.release_sha ?? "") ||
        !Number.isSafeInteger(manifest.run_id) || manifest.run_id < 1) failEudiEvidence("invalid_release_identity");
    const releaseSha = manifest.release_sha;
    verifyAttestationDocument(manifest, { repository: REPOSITORY, runId: manifest.run_id, releaseSha, releaseVersion: version });
    await verifyReleaseTag({ env: { ...env, RELEASE_SHA: releaseSha, RELEASE_VERSION: version } });
    const workflow = github(`repos/${REPOSITORY}/actions/workflows/crates-package-preflight.yml`);
    if (!isRecord(workflow) || !Number.isSafeInteger(workflow.id) || workflow.id < 1) failEudiEvidence("invalid_preflight_workflow");
    const run = github(`repos/${REPOSITORY}/actions/runs/${manifest.run_id}`);
    verifyWorkflowRun(run, { workflowId: workflow.id, runId: manifest.run_id, releaseSha });
    const expectedFiles = [...manifest.crates.map((item) => item.file), "crates-preflight.json"].sort();
    if (JSON.stringify(readdirSync(scratch).sort()) !== JSON.stringify(expectedFiles)) {
      failEudiEvidence("release_archive_set_mismatch");
    }
    for (const item of manifest.crates) regularBytes(join(scratch, item.file), MAX_ARCHIVE_BYTES);
    verifyAttestedCrateArchives(manifest, scratch);
    for (const file of expectedFiles) {
      command("gh", ["attestation", "verify", join(scratch, file), "--repo", REPOSITORY,
        "--signer-workflow", `${REPOSITORY}/.github/workflows/crates-package-preflight.yml`,
        "--source-digest", releaseSha, "--source-ref", "refs/heads/main", "--deny-self-hosted-runners"]);
    }
    // Compare the immutable registry checksum, not a release-page success label.
    for (const item of manifest.crates) {
      const name = item.file.slice(0, -`-${version}.crate`.length);
      let response;
      try {
        response = await fetch(`https://crates.io/api/v1/crates/${name}/${version}`, {
          headers: { "User-Agent": "ReallyMe-Wallet-Conformance/1.0" },
          redirect: "error", signal: AbortSignal.timeout(30_000),
        });
      } catch { failEudiEvidence("registry_evidence_unavailable"); }
      if (response.status !== 200) failEudiEvidence("registry_evidence_unavailable");
      const reader = response.body?.getReader();
      if (reader === undefined) failEudiEvidence("invalid_registry_response");
      const chunks = [];
      let size = 0;
      try {
        for (;;) {
          const chunk = await reader.read();
          if (chunk.done) break;
          size += chunk.value.length;
          if (!Number.isSafeInteger(size) || size > MAX_JSON_BYTES) failEudiEvidence("invalid_registry_response");
          chunks.push(chunk.value);
        }
      } finally { await reader.cancel(); }
      verifyRegistryVersion(decodeJson(Buffer.concat(chunks).toString("utf8")), name, version, item.sha256);
    }
    const jobs = github(`repos/${REPOSITORY}/actions/runs/${manifest.run_id}/attempts/1/jobs?per_page=100`);
    const { checks, evidence } = derivePreflightChecks(jobs, { runId: manifest.run_id, releaseSha });
    for (const item of evidence) writeFileSync(join(scratch, item.file), item.bytes, { flag: "wx", mode: 0o600 });
    const sourceLocks = {
      eudi_sources_sha256: sha256(regularBytes(join(framework, "upstream/eudi/sources.lock.json"), MAX_JSON_BYTES)),
      eudi_legal_sources_sha256: sha256(regularBytes(join(framework, "upstream/eudi/legal-sources.lock.json"), MAX_JSON_BYTES)),
      eudi_publications_sha256: sha256(regularBytes(join(framework, "references/eudi-publications.lock.json"), MAX_JSON_BYTES)),
    };
    const lock = github(`repos/${REPOSITORY}/contents/Cargo.lock?ref=${releaseSha}`);
    if (!isRecord(lock) || lock.encoding !== "base64" || typeof lock.content !== "string" ||
        !Number.isSafeInteger(lock.size) || lock.size < 1 || lock.size > MAX_JSON_BYTES) {
      failEudiEvidence("invalid_release_lock");
    }
    const encodedLock = lock.content.replaceAll("\n", "");
    const lockBytes = Buffer.from(encodedLock, "base64");
    if (lockBytes.length !== lock.size || lockBytes.toString("base64") !== encodedLock) {
      failEudiEvidence("invalid_release_lock");
    }
    // New output directories prevent stale inputs from a prior candidate being reused.
    mkdirSync(output, { mode: 0o700 });
    const bundle = join(output, "wallet-release");
    command("tar", ["-cf", bundle, "-C", scratch, "--", ...expectedFiles, ...evidence.map((item) => item.file)]);
    const { attestationBytes, deploymentBytes } = buildEudiDeploymentInputs({
      version, releaseSha, bundleHash: sha256(regularBytes(bundle, MAX_ARCHIVE_BYTES * 2)),
      cargoLockHash: sha256(lockBytes), sourceLocks, checks, createdAt: new Date().toISOString(),
    });
    writeFileSync(join(output, "wallet-attestation.json"), attestationBytes, { flag: "wx", mode: 0o600 });
    writeFileSync(join(output, "deployment.json"), deploymentBytes, { flag: "wx", mode: 0o600 });
    command("python3", [join(framework, "scripts/verify_eudi_wallet_deployment_manifest.py"), "--manifest", join(output, "deployment.json")]);
    command("python3", [join(framework, "scripts/verify_component_attestation.py"), "--attestation", join(output, "wallet-attestation.json")]);
    return { releaseSha, version, preflightRun: manifest.run_id, verifiedCrates: manifest.crates.length };
  } finally { rmSync(scratch, { recursive: true, force: true }); }
};

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
  try { console.log(JSON.stringify(await prepareEudiReleaseInputs())); }
  catch (error) {
    const code = error instanceof EudiReleaseEvidenceError ? error.code : "release_evidence_validation_failed";
    console.error(`EUDI release input preparation failed: ${code}`);
    process.exitCode = 1;
  }
}

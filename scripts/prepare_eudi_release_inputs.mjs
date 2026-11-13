#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import {
  appendFileSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifyAttestationDocument, verifyAttestedCrateArchives, verifyWorkflowRun,
} from "./verify_release_attestation.mjs";
import { verifyReleaseTag } from "./verify_release_tag.mjs";
import {
  buildEudiDeploymentInputs, derivePreflightChecks, deriveReleaseToolchain, EudiReleaseEvidenceError,
  failEudiEvidence, isRecord, sha256, verifyPublishedRelease, verifyRegistryVersion,
} from "./eudi_release_evidence.mjs";

const REPOSITORY = "reallyme/wallet";
const MAX_COMMAND_BYTES = 2_097_152;
const MAX_JSON_BYTES = 1_048_576;
const MAX_TOOLCHAIN_SOURCE_BYTES = 16_384;
const MAX_POLICY_SOURCE_BYTES = 131_072;
const MAX_ARCHIVE_BYTES = 16_777_216;
const COMMAND_TIMEOUT_MS = 120_000;
const FULL_SHA = /^[0-9a-f]{40}$/u;
const VERSION = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const PACKAGE_NAME = /^reallyme-wallet(?:-[a-z0-9][a-z0-9-]{0,63})?$/u;

const command = (program, args, env = process.env) => {
  const result = spawnSync(program, args, {
    encoding: "utf8", maxBuffer: MAX_COMMAND_BYTES, timeout: COMMAND_TIMEOUT_MS,
    env,
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
const releaseSourceBytes = (path, releaseSha, maximum = MAX_TOOLCHAIN_SOURCE_BYTES) => {
  const source = github(`repos/${REPOSITORY}/contents/${path}?ref=${releaseSha}`);
  if (!isRecord(source) || source.encoding !== "base64" || typeof source.content !== "string" ||
      source.content.length > Math.ceil(maximum / 3) * 4 + 4 ||
      !Number.isSafeInteger(source.size) || source.size < 1 || source.size > maximum) {
    failEudiEvidence("invalid_release_source");
  }
  const encoded = source.content.replaceAll("\n", "");
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.length !== source.size || bytes.toString("base64") !== encoded) {
    failEudiEvidence("invalid_release_source");
  }
  return bytes;
};

const parseTargetPolicy = (bytes, expectedVersion) => {
  const policy = decodeJson(bytes.toString("utf8"));
  const packages = isRecord(policy) ? policy.authorized_public_packages : undefined;
  if (policy?.release_version !== expectedVersion || !Array.isArray(packages) ||
      packages.length === 0 || packages.length > 128 ||
      packages.some((name) => typeof name !== "string" || !PACKAGE_NAME.test(name)) ||
      new Set(packages).size !== packages.length) {
    failEudiEvidence("invalid_target_package_policy");
  }
  return [...packages].sort();
};

const parseReleaseVersion = (release) => {
  const tag = isRecord(release) && typeof release.tag_name === "string" ? release.tag_name : "";
  const match = /^reallyme-wallet-v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))$/u.exec(tag);
  if (match === null || !Number.isSafeInteger(release.id) || release.id < 1) {
    failEudiEvidence("invalid_published_release");
  }
  verifyPublishedRelease(release, tag);
  return { releaseId: release.id, releaseRef: tag, version: match[1] };
};

const writeTargetOutputs = (path, target) => {
  if (typeof path !== "string" || path.length === 0) failEudiEvidence("missing_github_output");
  const releaseId = target.mode === "published" ? String(target.release_id) : "";
  const releaseRef = target.mode === "published" ? target.release_ref : "";
  appendFileSync(path,
    `target_mode=${target.mode}\ntarget_commit=${target.commit}\ntarget_version=${target.version}\n` +
    `preflight_run_id=${target.preflight_run_id}\nrelease_id=${releaseId}\nrelease_ref=${releaseRef}\n`,
    { encoding: "utf8" });
};

/** Materialize immutable package evidence for one caller-selected target mode. */
export const prepareEudiReleaseInputs = async ({ env = process.env } = {}) => {
  const frameworkCommit = env.FRAMEWORK_COMMIT;
  const targetMode = env.TARGET_MODE;
  if (env.GITHUB_REPOSITORY !== REPOSITORY || typeof env.GH_TOKEN !== "string" || env.GH_TOKEN.length === 0 ||
      !FULL_SHA.test(frameworkCommit ?? "") || typeof env.RUNNER_TEMP !== "string" ||
      typeof env.EUDI_FRAMEWORK_PATH !== "string" || typeof env.EUDI_INPUT_DIRECTORY !== "string" ||
      !["candidate", "published"].includes(targetMode)) {
    failEudiEvidence("invalid_eudi_runner_environment");
  }
  const framework = resolve(env.EUDI_FRAMEWORK_PATH);
  if (command("git", ["-C", framework, "rev-parse", "HEAD"]).trim() !== frameworkCommit ||
      command("git", ["-C", framework, "status", "--porcelain"]).trim() !== "") {
    failEudiEvidence("framework_checkout_mismatch");
  }
  const output = resolve(env.EUDI_INPUT_DIRECTORY);
  const scratch = mkdtempSync(join(resolve(env.RUNNER_TEMP), "wallet-package-evidence-"));
  try {
    let target;
    let packageNames;
    if (targetMode === "candidate") {
      const releaseSha = env.EUDI_TARGET_COMMIT;
      if (typeof releaseSha !== "string" || !FULL_SHA.test(releaseSha) || env.EUDI_WALLET_RELEASE) {
        failEudiEvidence("invalid_candidate_identity");
      }
      // A retest may select an older main commit. Its package policy, not the
      // dispatcher's current policy, defines the version and package inventory.
      const targetPolicyBytes = releaseSourceBytes(
        "conformance/features/wallet-package-policy-v1.json", releaseSha, MAX_POLICY_SOURCE_BYTES,
      );
      const targetPolicy = decodeJson(targetPolicyBytes.toString("utf8"));
      const version = isRecord(targetPolicy) ? targetPolicy.release_version : undefined;
      if (typeof version !== "string" || !VERSION.test(version)) failEudiEvidence("invalid_candidate_identity");
      packageNames = parseTargetPolicy(targetPolicyBytes, version);
      if (typeof env.PREFLIGHT_RUN_ID !== "string" || !/^[1-9][0-9]*$/u.test(env.PREFLIGHT_RUN_ID) ||
          !Number.isSafeInteger(Number(env.PREFLIGHT_RUN_ID))) {
        failEudiEvidence("invalid_candidate_preflight");
      }
      const runId = Number(env.PREFLIGHT_RUN_ID);
      command("gh", ["run", "download", String(runId), "--repo", REPOSITORY,
        "--name", `reallyme-wallet-crates-preflight-${version}-${releaseSha}`, "--dir", scratch]);
      command("gh", ["run", "download", String(runId), "--repo", REPOSITORY,
        "--name", `reallyme-wallet-crate-archives-${version}-${releaseSha}`, "--dir", scratch]);
      target = { mode: "candidate", version, commit: releaseSha, preflight_run_id: runId };
    } else {
      if (env.EUDI_TARGET_COMMIT || env.PREFLIGHT_RUN_ID) failEudiEvidence("published_target_override");
      if (typeof env.EUDI_WALLET_RELEASE !== "string" ||
          !/^reallyme-wallet-v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u.test(env.EUDI_WALLET_RELEASE)) {
        failEudiEvidence("invalid_published_release_selection");
      }
      const release = github(`repos/${REPOSITORY}/releases/tags/${env.EUDI_WALLET_RELEASE}`);
      const { releaseId, releaseRef, version } = parseReleaseVersion(release);
      if (releaseRef !== env.EUDI_WALLET_RELEASE) failEudiEvidence("published_release_selection_mismatch");
      command("gh", ["release", "download", releaseRef, "--repo", REPOSITORY,
        "--dir", scratch, "--pattern", "crates-preflight.json", "--pattern", "*.crate"]);
      const preliminaryManifest = decodeJson(
        regularBytes(join(scratch, "crates-preflight.json"), MAX_JSON_BYTES).toString("utf8"),
      );
      if (!isRecord(preliminaryManifest) || !FULL_SHA.test(preliminaryManifest.release_sha ?? "") ||
          !Number.isSafeInteger(preliminaryManifest.run_id) || preliminaryManifest.run_id < 1) {
        failEudiEvidence("invalid_release_identity");
      }
      packageNames = parseTargetPolicy(
        releaseSourceBytes("conformance/features/wallet-package-policy-v1.json",
          preliminaryManifest.release_sha, MAX_POLICY_SOURCE_BYTES),
        version,
      );
      target = {
        mode: "published", version, commit: preliminaryManifest.release_sha,
        preflight_run_id: preliminaryManifest.run_id, release_id: releaseId, release_ref: releaseRef,
      };
      await verifyReleaseTag({
        env: { ...env, RELEASE_SHA: target.commit, RELEASE_VERSION: target.version },
      });
    }
    const manifestPath = join(scratch, "crates-preflight.json");
    const manifest = decodeJson(regularBytes(manifestPath, MAX_JSON_BYTES).toString("utf8"));
    verifyAttestationDocument(manifest, {
      repository: REPOSITORY, runId: target.preflight_run_id, releaseSha: target.commit,
      releaseVersion: target.version, packageNames,
    });
    const workflow = github(`repos/${REPOSITORY}/actions/workflows/crates-package-preflight.yml`);
    if (!isRecord(workflow) || !Number.isSafeInteger(workflow.id) || workflow.id < 1) failEudiEvidence("invalid_preflight_workflow");
    const run = github(`repos/${REPOSITORY}/actions/runs/${target.preflight_run_id}`);
    verifyWorkflowRun(run, {
      workflowId: workflow.id, runId: target.preflight_run_id, releaseSha: target.commit,
    });
    if (target.mode === "candidate") {
      const ancestry = github(`repos/${REPOSITORY}/compare/${target.commit}...main`);
      if (!isRecord(ancestry) || !["ahead", "identical"].includes(ancestry.status) ||
          !isRecord(ancestry.merge_base_commit) || ancestry.merge_base_commit.sha !== target.commit) {
        failEudiEvidence("candidate_is_not_main_ancestor");
      }
    }
    const expectedFiles = [...manifest.crates.map((item) => item.file), "crates-preflight.json"].sort();
    if (JSON.stringify(readdirSync(scratch).sort()) !== JSON.stringify(expectedFiles)) {
      failEudiEvidence("release_archive_set_mismatch");
    }
    for (const item of manifest.crates) regularBytes(join(scratch, item.file), MAX_ARCHIVE_BYTES);
    verifyAttestedCrateArchives(manifest, scratch);
    for (const file of expectedFiles) {
      command("gh", ["attestation", "verify", join(scratch, file), "--repo", REPOSITORY,
        "--signer-workflow", `${REPOSITORY}/.github/workflows/crates-package-preflight.yml`,
        "--source-digest", target.commit, "--source-ref", "refs/heads/main", "--deny-self-hosted-runners"]);
    }
    if (target.mode === "published") {
      // Candidate mode must remain independent of crates.io publication state.
      for (const item of manifest.crates) {
        const name = item.file.slice(0, -`-${target.version}.crate`.length);
        let response;
        try {
          response = await fetch(`https://crates.io/api/v1/crates/${name}/${target.version}`, {
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
        verifyRegistryVersion(
          decodeJson(Buffer.concat(chunks).toString("utf8")), name, target.version, item.sha256,
        );
      }
    }
    const jobs = github(
      `repos/${REPOSITORY}/actions/runs/${target.preflight_run_id}/attempts/1/jobs?per_page=100`,
    );
    const { checks, evidence } = derivePreflightChecks(jobs, {
      runId: target.preflight_run_id, releaseSha: target.commit,
    });
    for (const item of evidence) writeFileSync(join(scratch, item.file), item.bytes, { flag: "wx", mode: 0o600 });
    const sourceLocks = {
      eudi_sources_sha256: sha256(regularBytes(join(framework, "upstream/eudi/sources.lock.json"), MAX_JSON_BYTES)),
      eudi_legal_sources_sha256: sha256(regularBytes(join(framework, "upstream/eudi/legal-sources.lock.json"), MAX_JSON_BYTES)),
      eudi_publications_sha256: sha256(regularBytes(join(framework, "references/eudi-publications.lock.json"), MAX_JSON_BYTES)),
    };
    const lockBytes = releaseSourceBytes("Cargo.lock", target.commit, MAX_JSON_BYTES);
    const toolchainVersion = deriveReleaseToolchain(
      releaseSourceBytes("rust-toolchain.toml", target.commit).toString("utf8"),
      releaseSourceBytes(".github/workflows/crates-package-preflight.yml", target.commit).toString("utf8"),
    );
    // New output directories prevent stale inputs from a prior candidate being reused.
    mkdirSync(output, { mode: 0o700 });
    const bundle = join(output, "wallet-release");
    // macOS metadata sidecars would add unreviewed members to the exact bundle.
    command("tar", ["-cf", bundle, "-C", scratch, "--", ...expectedFiles, ...evidence.map((item) => item.file)],
      { ...env, COPYFILE_DISABLE: "1" });
    const { attestationBytes, deploymentBytes } = buildEudiDeploymentInputs({
      target, bundleHash: sha256(regularBytes(bundle, MAX_ARCHIVE_BYTES * 2)),
      cargoLockHash: sha256(lockBytes), sourceLocks, checks, createdAt: new Date().toISOString(), toolchainVersion,
    });
    writeFileSync(join(output, "wallet-attestation.json"), attestationBytes, { flag: "wx", mode: 0o600 });
    writeFileSync(join(output, "deployment.json"), deploymentBytes, { flag: "wx", mode: 0o600 });
    command("python3", [join(framework, "scripts/verify_eudi_wallet_deployment_manifest.py"), "--manifest", join(output, "deployment.json")]);
    command("python3", [join(framework, "scripts/verify_component_attestation.py"),
      "--attestation", join(output, "wallet-attestation.json")]);
    if (env.EUDI_WRITE_GITHUB_OUTPUT === "1") writeTargetOutputs(env.GITHUB_OUTPUT, target);
    return { target, verifiedCrates: manifest.crates.length };
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

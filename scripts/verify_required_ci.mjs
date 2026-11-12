#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const FULL_SHA_PATTERN = /^[0-9a-f]{40}$/u;
const INTEGER_PATTERN = /^(?:0|[1-9][0-9]*)$/u;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const MAX_OUTPUT_BYTES = 1_048_576;
const MAX_COMMAND_TIMEOUT_MS = 60_000;
const MAX_WAIT_SECONDS = 7_200;
const MAX_POLL_SECONDS = 300;
const DEFAULT_POLL_SECONDS = 20;
const MAX_JOB_COUNT = 100;
const MAX_STEP_COUNT = 100;
const MAX_NAME_CHARACTERS = 256;
const REQUIRED_FUZZ_JOBS = Object.freeze([
  "fuzz target build",
  "scheduled fuzz (wallet_proto_decode)",
  "scheduled fuzz (wallet_proto_json)",
  "scheduled fuzz (wallet_identifier)",
  "scheduled fuzz (wallet_state_machine)",
]);

export const REQUIRED_WORKFLOWS = Object.freeze([
  Object.freeze({ outputName: "rust_ci_run_id", workflowFile: "rust-ci.yml" }),
  Object.freeze({ outputName: "protobuf_ci_run_id", workflowFile: "protobuf-ci.yml" }),
  Object.freeze({ outputName: "fuzz_run_id", workflowFile: "fuzz.yml" }),
]);

export class RequiredCiError extends Error {
  constructor(code) {
    super(code);
    this.name = "RequiredCiError";
    this.code = code;
  }
}

const fail = (code, workflowFile) => {
  throw new RequiredCiError(workflowFile === undefined ? code : `${code}:${workflowFile}`);
};
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

const parseSeconds = (value, defaultValue, code, maximum) => {
  if (value === undefined || value === "") return defaultValue;
  if (typeof value !== "string" || !INTEGER_PATTERN.test(value)) fail(code);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) fail(code);
  return parsed;
};

const sleepSeconds = (seconds) => {
  if (seconds > 0) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, seconds * 1_000);
  }
};

const runJson = (arguments_, code) => {
  const result = spawnSync("gh", arguments_, {
    encoding: "utf8",
    maxBuffer: MAX_OUTPUT_BYTES,
    timeout: MAX_COMMAND_TIMEOUT_MS,
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (result.error !== undefined || result.status !== 0 || typeof result.stdout !== "string") {
    fail(code);
  }
  try {
    return JSON.parse(result.stdout);
  } catch {
    fail(code);
  }
};

const validateRun = (value) => {
  if (!isRecord(value)) fail("invalid-required-ci-run-list");
  const run = {
    conclusion: value.conclusion,
    event: value.event,
    headBranch: value.head_branch,
    headSha: value.head_sha,
    id: value.id,
    path: value.path,
    runAttempt: value.run_attempt,
    status: value.status,
    workflowId: value.workflow_id,
  };
  if (
    !Number.isSafeInteger(run.id) || run.id < 1 ||
    !Number.isSafeInteger(run.workflowId) || run.workflowId < 1 ||
    !Number.isSafeInteger(run.runAttempt) || run.runAttempt < 1 ||
    typeof run.event !== "string" || typeof run.headBranch !== "string" ||
    typeof run.headSha !== "string" || typeof run.path !== "string" ||
    typeof run.status !== "string" ||
    (run.conclusion !== null && typeof run.conclusion !== "string")
  ) {
    fail("invalid-required-ci-run-list");
  }
  return run;
};

export const selectRequiredCiRun = (value, expected) => {
  if (!isRecord(value) || !Array.isArray(value.workflow_runs)) {
    fail("invalid-required-ci-run-list");
  }
  const latest = value.workflow_runs
    .map(validateRun)
    .filter((run) =>
      run.workflowId === expected.workflowId &&
      (expected.workflowFile === "fuzz.yml"
        ? run.event === "workflow_dispatch"
        : ["push", "workflow_dispatch"].includes(run.event)) &&
      run.headBranch === "main" && run.headSha === expected.releaseSha &&
      run.path === `.github/workflows/${expected.workflowFile}`,
    )
    .sort((left, right) => left.id === right.id
      ? right.runAttempt - left.runAttempt
      : right.id - left.id)[0];
  if (latest === undefined) fail("missing-required-ci-run", expected.workflowFile);
  if (latest.runAttempt !== 1) fail("required-ci-rerun-not-accepted", expected.workflowFile);
  if (latest.status !== "completed") fail("required-ci-run-pending", expected.workflowFile);
  if (latest.conclusion === "failure") fail("required-ci-run-failed", expected.workflowFile);
  if (latest.conclusion === "cancelled") fail("required-ci-run-cancelled", expected.workflowFile);
  if (latest.conclusion !== "success") fail("required-ci-run-not-successful", expected.workflowFile);
  return latest;
};

/** A successful smoke build cannot stand in for all time-boxed campaigns. */
export const verifyFuzzCampaignJobs = (value, run) => {
  const rejected = () => fail("invalid-required-fuzz-campaigns", "fuzz.yml");
  if (!isRecord(run) || !Number.isSafeInteger(run.id) || run.id < 1 ||
      typeof run.headSha !== "string" || !FULL_SHA_PATTERN.test(run.headSha) ||
      run.event !== "workflow_dispatch" ||
      run.runAttempt !== 1 || run.headBranch !== "main" ||
      run.path !== ".github/workflows/fuzz.yml" || run.status !== "completed" ||
      run.conclusion !== "success" || !isRecord(value) || !Array.isArray(value.jobs) ||
      value.total_count !== value.jobs.length || value.jobs.length > MAX_JOB_COUNT ||
      value.jobs.length !== REQUIRED_FUZZ_JOBS.length) rejected();
  const seenNames = new Set();
  const seenIds = new Set();
  for (const job of value.jobs) {
    if (!isRecord(job) || !Number.isSafeInteger(job.id) || job.id < 1 || seenIds.has(job.id) ||
        typeof job.name !== "string" || job.name.length > MAX_NAME_CHARACTERS ||
        !REQUIRED_FUZZ_JOBS.includes(job.name) || seenNames.has(job.name) ||
        job.run_id !== run.id || job.run_attempt !== 1 || job.head_sha !== run.headSha ||
        job.status !== "completed" || job.conclusion !== "success" ||
        !Array.isArray(job.steps) || job.steps.length > MAX_STEP_COUNT) rejected();
    seenIds.add(job.id);
    seenNames.add(job.name);
    const requiredSteps = job.name === "fuzz target build"
      ? ["Build fuzz targets", "Upload scheduled fuzz executables", "Record staged fuzz executable digests"]
      : ["Download fuzz executables", "Run time-boxed fuzz target"];
    const steps = new Map();
    const numbers = new Set();
    for (const step of job.steps) {
      if (!isRecord(step) || typeof step.name !== "string" || step.name.length === 0 ||
          step.name.length > MAX_NAME_CHARACTERS || steps.has(step.name) ||
          step.status !== "completed" || !["success", "skipped"].includes(step.conclusion) ||
          !Number.isSafeInteger(step.number) || step.number < 1 || numbers.has(step.number)) rejected();
      steps.set(step.name, step);
      numbers.add(step.number);
    }
    for (const name of requiredSteps) {
      const step = steps.get(name);
      if (step?.status !== "completed" || step.conclusion !== "success") rejected();
    }
  }
};

export const resolveRequiredCi = ({ repository, releaseSha, query = runJson }) => REQUIRED_WORKFLOWS.map((requirement) => {
  const workflow = query(
    ["api", `repos/${repository}/actions/workflows/${requirement.workflowFile}`],
    `required-ci-workflow-query-failed:${requirement.workflowFile}`,
  );
  if (!isRecord(workflow) || !Number.isSafeInteger(workflow.id) || workflow.id < 1) {
    fail("invalid-required-ci-workflow-response", requirement.workflowFile);
  }
  const runs = query(
    ["api", `repos/${repository}/actions/workflows/${workflow.id}/runs?branch=main&head_sha=${releaseSha}&per_page=100`],
    `required-ci-run-list-query-failed:${requirement.workflowFile}`,
  );
  const selected = selectRequiredCiRun(runs, {
    releaseSha,
    workflowFile: requirement.workflowFile,
    workflowId: workflow.id,
  });
  if (requirement.workflowFile === "fuzz.yml") {
    const jobs = query(
      ["api", `repos/${repository}/actions/runs/${selected.id}/attempts/1/jobs?per_page=100`],
      "required-fuzz-jobs-query-failed:fuzz.yml",
    );
    verifyFuzzCampaignJobs(jobs, selected);
  }
  return selected;
});

const isWaitable = (error) => error instanceof RequiredCiError &&
  (error.code.startsWith("missing-required-ci-run:") ||
   error.code.startsWith("required-ci-run-pending:"));

export const resolveRequiredCiWithWait = ({
  pollSeconds,
  releaseSha,
  repository,
  waitSeconds,
  now = Date.now,
  onWait = () => {},
  resolve = resolveRequiredCi,
  sleep = sleepSeconds,
}) => {
  const deadline = now() + waitSeconds * 1_000;
  for (;;) {
    try {
      return resolve({ repository, releaseSha });
    } catch (error) {
      if (!isWaitable(error) || now() >= deadline) throw error;
      const remainingSeconds = Math.max(1, Math.ceil((deadline - now()) / 1_000));
      const retrySeconds = Math.min(pollSeconds, remainingSeconds);
      onWait({ code: error.code, remainingSeconds, retrySeconds });
      sleep(retrySeconds);
    }
  }
};

export const verifyRequiredCi = ({ env = process.env, onWait } = {}) => {
  const repository = env.GITHUB_REPOSITORY;
  const releaseSha = env.RELEASE_SHA;
  if (typeof repository !== "string" || !REPOSITORY_PATTERN.test(repository)) fail("invalid-repository");
  if (typeof releaseSha !== "string" || !FULL_SHA_PATTERN.test(releaseSha)) fail("invalid-release-sha");
  if (env.GITHUB_SHA !== releaseSha) fail("workflow-head-mismatch");
  if (typeof env.GH_TOKEN !== "string" || env.GH_TOKEN.length === 0) fail("missing-github-token");
  const waitSeconds = parseSeconds(env.REQUIRED_CI_WAIT_SECONDS, 0, "invalid-required-ci-wait-seconds", MAX_WAIT_SECONDS);
  const pollSeconds = parseSeconds(env.REQUIRED_CI_POLL_SECONDS, DEFAULT_POLL_SECONDS, "invalid-required-ci-poll-seconds", MAX_POLL_SECONDS);
  if (waitSeconds > 0 && pollSeconds === 0) fail("invalid-required-ci-poll-seconds");
  return resolveRequiredCiWithWait({ onWait, pollSeconds, releaseSha, repository, waitSeconds });
};

export const formatRequiredCiOutputs = (runs) => {
  if (!Array.isArray(runs) || runs.length !== REQUIRED_WORKFLOWS.length) {
    fail("invalid-required-ci-output-set");
  }
  return runs.map((run, index) => {
    if (!isRecord(run) || !Number.isSafeInteger(run.id) || run.id < 1) {
      fail("invalid-required-ci-output-set");
    }
    return `${REQUIRED_WORKFLOWS[index].outputName}=${run.id}`;
  }).join("\n");
};

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  try {
    const runs = verifyRequiredCi({
      onWait: ({ code, remainingSeconds, retrySeconds }) => {
        console.log(`required CI evidence pending: ${code}; retrying in ${retrySeconds}s (${remainingSeconds}s remain)`);
      },
    });
    if (process.env.REQUIRED_CI_WRITE_GITHUB_OUTPUT === "1") {
      if (typeof process.env.GITHUB_OUTPUT !== "string" || process.env.GITHUB_OUTPUT.length === 0) {
        fail("missing-github-output");
      }
      appendFileSync(process.env.GITHUB_OUTPUT, `${formatRequiredCiOutputs(runs)}\n`, { encoding: "utf8" });
    }
    console.log("exact release commit has successful required workflow evidence");
  } catch (error) {
    const code = error instanceof RequiredCiError ? error.code : "unexpected-failure";
    console.error(`required CI verification failed: ${code}`);
    process.exit(1);
  }
}

#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import {
  formatRequiredCiOutputs,
  RequiredCiError,
  REQUIRED_WORKFLOWS,
  resolveRequiredCi,
  resolveRequiredCiWithWait,
  selectRequiredCiRun,
  verifyFuzzCampaignJobs,
} from "./verify_required_ci.mjs";

const RELEASE_SHA = "0123456789abcdef0123456789abcdef01234567";
const expected = { releaseSha: RELEASE_SHA, workflowFile: "fuzz.yml", workflowId: 41 };
const workflowRun = (overrides = {}) => ({
  conclusion: "success",
  event: "workflow_dispatch",
  head_branch: "main",
  head_sha: RELEASE_SHA,
  id: 100,
  path: ".github/workflows/fuzz.yml",
  run_attempt: 1,
  status: "completed",
  workflow_id: 41,
  ...overrides,
});

test("Rust and protobuf CI retain exact first-attempt push and dispatch evidence", () => {
  for (const workflowFile of ["rust-ci.yml", "protobuf-ci.yml"]) {
    for (const event of ["push", "workflow_dispatch"]) {
      const run = workflowRun({ event, path: `.github/workflows/${workflowFile}` });
      assert.equal(selectRequiredCiRun({ workflow_runs: [run] }, { ...expected, workflowFile }).event, event);
    }
  }
});

test("fuzz release evidence rejects push-only smoke runs and requires manual campaigns", () => {
  assert.throws(() => selectRequiredCiRun({ workflow_runs: [workflowRun({ event: "push" })] }, expected), {
    name: "RequiredCiError", code: "missing-required-ci-run:fuzz.yml",
  });
  const manual = workflowRun();
  const push = workflowRun({ id: 101, event: "push" });
  assert.equal(selectRequiredCiRun({ workflow_runs: [manual, push] }, expected).id, manual.id);
});

test("a newer failed manual campaign cannot be replaced by earlier success or newer smoke evidence", () => {
  assert.throws(() => selectRequiredCiRun({ workflow_runs: [
    workflowRun(), workflowRun({ id: 101, conclusion: "failure" }), workflowRun({ id: 102, event: "push" }),
  ] }, expected), { name: "RequiredCiError", code: "required-ci-run-failed:fuzz.yml" });
});

test("rejects terminal failures, pending evidence, reruns, and wrong source identity", () => {
  for (const [run, code] of [
    [workflowRun({ conclusion: "failure" }), "required-ci-run-failed:fuzz.yml"],
    [workflowRun({ conclusion: "cancelled" }), "required-ci-run-cancelled:fuzz.yml"],
    [workflowRun({ conclusion: null, status: "in_progress" }), "required-ci-run-pending:fuzz.yml"],
    [workflowRun({ run_attempt: 2 }), "required-ci-rerun-not-accepted:fuzz.yml"],
  ]) {
    assert.throws(
      () => selectRequiredCiRun({ workflow_runs: [run] }, expected),
      (error) => error instanceof RequiredCiError && error.code === code,
    );
  }
  for (const mismatch of [
    { event: "schedule" },
    { head_branch: "feature" },
    { head_sha: "fedcba9876543210fedcba9876543210fedcba98" },
    { path: ".github/workflows/other.yml" },
    { workflow_id: 42 },
  ]) {
    assert.throws(
      () => selectRequiredCiRun({ workflow_runs: [workflowRun(mismatch)] }, expected),
      RequiredCiError,
    );
  }
});

const selectedFuzzRun = () => selectRequiredCiRun({ workflow_runs: [workflowRun()] }, expected);
const fuzzJobs = (runId = 100) => ({
  total_count: 5,
  jobs: ["fuzz target build", "scheduled fuzz (wallet_proto_decode)", "scheduled fuzz (wallet_proto_json)",
    "scheduled fuzz (wallet_identifier)", "scheduled fuzz (wallet_state_machine)"].map((name, index) => ({
    id: index + 1, run_id: runId, run_attempt: 1, head_sha: RELEASE_SHA, name,
    status: "completed", conclusion: "success",
    steps: (index === 0
      ? ["Build fuzz targets", "Upload scheduled fuzz executables", "Record staged fuzz executable digests"]
      : ["Download fuzz executables", "Run time-boxed fuzz target"])
      .map((step, number) => ({ name: step, number: number + 1, status: "completed", conclusion: "success" })),
  })),
});

test("all four exact-commit fuzz campaigns and build evidence must complete successfully", () => {
  const jobs = fuzzJobs();
  jobs.jobs.reverse();
  jobs.jobs[0].steps.push({ name: "Upload crash artifacts", number: 3, status: "completed", conclusion: "skipped" });
  assert.doesNotThrow(() => verifyFuzzCampaignJobs(jobs, selectedFuzzRun()));
});

test("missing, duplicate, foreign, failed, skipped and incomplete matrix evidence fails closed", () => {
  const mutations = [
    (value) => { value.jobs.pop(); value.total_count -= 1; },
    (value) => { value.total_count += 1; },
    (value) => { value.jobs[4] = structuredClone(value.jobs[3]); },
    (value) => { value.jobs[4].name = "scheduled fuzz (unreviewed_target)"; },
    (value) => { value.jobs[4].id = value.jobs[3].id; },
    (value) => { value.jobs[4].run_id += 1; },
    (value) => { value.jobs[4].head_sha = "f".repeat(40); },
    (value) => { value.jobs[4].run_attempt = 2; },
    (value) => { value.jobs[4].status = "in_progress"; },
    (value) => { value.jobs[4].conclusion = "failure"; },
    (value) => { value.jobs[4].conclusion = "skipped"; },
    (value) => { value.jobs[4].conclusion = "cancelled"; },
    (value) => { value.jobs[4].steps.pop(); },
    (value) => { value.jobs[4].steps[1].conclusion = "skipped"; },
    (value) => { value.jobs[4].steps[1].conclusion = "failure"; },
    (value) => { value.jobs[4].steps[1].status = "in_progress"; },
    (value) => { value.jobs[4].steps.push(structuredClone(value.jobs[4].steps[1])); },
    (value) => { value.jobs[4].steps[1].number = 1; },
    (value) => { value.jobs[4].steps[1].name = "x".repeat(257); },
    (value) => { value.jobs[4].steps = Array(101).fill(value.jobs[4].steps[0]); },
    (value) => { value.jobs[0].steps[1].conclusion = "skipped"; },
  ];
  for (const mutate of mutations) {
    const value = fuzzJobs();
    mutate(value);
    assert.throws(() => verifyFuzzCampaignJobs(value, selectedFuzzRun()), {
      name: "RequiredCiError", code: "invalid-required-fuzz-campaigns:fuzz.yml",
    });
  }
  for (const value of [null, {}, { total_count: 5, jobs: [] }, { total_count: 101, jobs: Array(101).fill(null) }]) {
    assert.throws(() => verifyFuzzCampaignJobs(value, selectedFuzzRun()), RequiredCiError);
  }
  for (const run of [null, {}, { ...selectedFuzzRun(), event: "push" }, { ...selectedFuzzRun(), runAttempt: 2 }]) {
    assert.throws(() => verifyFuzzCampaignJobs(fuzzJobs(), run), RequiredCiError);
  }
});

test("a soft-failed extra step cannot be hidden by a successful campaign job", () => {
  for (const state of [
    { status: "completed", conclusion: "failure" },
    { status: "completed", conclusion: "cancelled" },
    { status: "completed", conclusion: "neutral" },
    { status: "in_progress", conclusion: "success" },
  ]) {
    const value = fuzzJobs();
    value.jobs[4].steps.push({ name: "Optional campaign diagnostics", number: 3, ...state });
    assert.throws(() => verifyFuzzCampaignJobs(value, selectedFuzzRun()), {
      name: "RequiredCiError", code: "invalid-required-fuzz-campaigns:fuzz.yml",
    });
  }
});

test("release prerequisite resolution actually queries and validates the selected campaign jobs", () => {
  const resolve = (scenario) => {
    const calls = [];
    const query = (args) => {
      const endpoint = args[1];
      calls.push(endpoint);
      for (const [index, { workflowFile }] of REQUIRED_WORKFLOWS.entries()) {
        const workflowId = index + 1;
        if (endpoint === `repos/reallyme/wallet/actions/workflows/${workflowFile}`) return { id: workflowId };
        if (endpoint === `repos/reallyme/wallet/actions/workflows/${workflowId}/runs?branch=main&head_sha=${RELEASE_SHA}&per_page=100`) {
          return { workflow_runs: [workflowRun({
            id: index + 200, workflow_id: workflowId, path: `.github/workflows/${workflowFile}`,
            event: workflowFile === "fuzz.yml" && scenario !== "smoke" ? "workflow_dispatch" : "push",
          })] };
        }
      }
      if (endpoint === "repos/reallyme/wallet/actions/runs/202/attempts/1/jobs?per_page=100") {
        const jobs = fuzzJobs(202);
        if (scenario === "missing-campaign") { jobs.jobs.pop(); jobs.total_count -= 1; }
        return jobs;
      }
      assert.fail("unexpected prerequisite evidence query");
    };
    const runs = resolveRequiredCi({ repository: "reallyme/wallet", releaseSha: RELEASE_SHA, query });
    return { runs, calls };
  };
  const valid = resolve("success");
  assert.deepEqual(valid.runs.map(({ id }) => id), [200, 201, 202]);
  assert.equal(valid.calls.filter((endpoint) => endpoint.includes("/jobs?")).length, 1);
  assert.throws(() => resolve("smoke"), { name: "RequiredCiError", code: "missing-required-ci-run:fuzz.yml" });
  assert.throws(() => resolve("missing-campaign"), {
    name: "RequiredCiError", code: "invalid-required-fuzz-campaigns:fuzz.yml",
  });
});

test("serializes the fixed prerequisite mapping", () => {
  assert.deepEqual(REQUIRED_WORKFLOWS.map(({ workflowFile }) => workflowFile), [
    "rust-ci.yml",
    "protobuf-ci.yml",
    "fuzz.yml",
  ]);
  assert.equal(
    formatRequiredCiOutputs([{ id: 11 }, { id: 12 }, { id: 13 }]),
    "rust_ci_run_id=11\nprotobuf_ci_run_id=12\nfuzz_run_id=13",
  );
  assert.throws(() => formatRequiredCiOutputs([{ id: 11 }]), RequiredCiError);
});

test("bounded polling waits only for missing or pending evidence", () => {
  let now = 1_000;
  let attempts = 0;
  const sleeps = [];
  const result = resolveRequiredCiWithWait({
    pollSeconds: 20,
    releaseSha: RELEASE_SHA,
    repository: "reallyme/wallet",
    waitSeconds: 30,
    now: () => now,
    resolve: () => {
      attempts += 1;
      if (attempts === 1) throw new RequiredCiError("required-ci-run-pending:fuzz.yml");
      return [{ id: 11 }, { id: 12 }, { id: 13 }];
    },
    sleep: (seconds) => {
      sleeps.push(seconds);
      now += seconds * 1_000;
    },
  });
  assert.deepEqual(result, [{ id: 11 }, { id: 12 }, { id: 13 }]);
  assert.deepEqual(sleeps, [20]);

  assert.throws(
    () => resolveRequiredCiWithWait({
      pollSeconds: 20,
      releaseSha: RELEASE_SHA,
      repository: "reallyme/wallet",
      waitSeconds: 60,
      resolve: () => { throw new RequiredCiError("required-ci-run-failed:fuzz.yml"); },
      sleep: () => assert.fail("terminal failures must not be retried"),
    }),
    RequiredCiError,
  );
});

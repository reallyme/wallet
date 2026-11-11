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
  resolveRequiredCiWithWait,
  selectRequiredCiRun,
} from "./verify_required_ci.mjs";

const RELEASE_SHA = "0123456789abcdef0123456789abcdef01234567";
const expected = { releaseSha: RELEASE_SHA, workflowFile: "fuzz.yml", workflowId: 41 };
const workflowRun = (overrides = {}) => ({
  conclusion: "success",
  event: "push",
  head_branch: "main",
  head_sha: RELEASE_SHA,
  id: 100,
  path: ".github/workflows/fuzz.yml",
  run_attempt: 1,
  status: "completed",
  workflow_id: 41,
  ...overrides,
});

test("accepts exact successful first-attempt push and dispatch evidence", () => {
  assert.equal(selectRequiredCiRun({ workflow_runs: [workflowRun()] }, expected).event, "push");
  assert.equal(
    selectRequiredCiRun({ workflow_runs: [workflowRun({ event: "workflow_dispatch" })] }, expected).event,
    "workflow_dispatch",
  );
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

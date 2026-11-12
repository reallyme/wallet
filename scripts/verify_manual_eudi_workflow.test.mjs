// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  MANUAL_EUDI_WORKFLOW_PATH,
  ManualEudiWorkflowError,
  verifyManualEudiWorkflow,
} from "./verify_manual_eudi_workflow.mjs";

const source = readFileSync(new URL(`../${MANUAL_EUDI_WORKFLOW_PATH}`, import.meta.url), "utf8");

test("hosted preparation and execution use one immutable framework revision", () => {
  const result = verifyManualEudiWorkflow(source);
  assert.match(result.frameworkCommit, /^[0-9a-f]{40}$/u);
  assert.deepEqual(verifyManualEudiWorkflow(source.replaceAll("\n", "\r\n")), result);
  assert.equal((source.match(new RegExp(result.frameworkCommit, "gu")) ?? []).length, 4);
  assert.doesNotMatch(source, /self-hosted|secrets:|\/protected-inputs/u);
});

for (const [name, before, after] of [
  ["push", "  workflow_dispatch:", "  workflow_dispatch:\n  push:"],
  ["pull request", "  workflow_dispatch:", "  workflow_dispatch:\n  pull_request:"],
  ["schedule", "  workflow_dispatch:", "  workflow_dispatch:\n  schedule:\n    - cron: '0 0 * * *'"],
  ["workflow completion", "  workflow_dispatch:", "  workflow_dispatch:\n  workflow_run:"],
  ["reusable entry point", "  workflow_dispatch:", "  workflow_dispatch:\n  workflow_call:"],
  ["dispatch inputs", "  workflow_dispatch:", "  workflow_dispatch:\n    inputs:\n      arbitrary_path:\n        type: string"],
  ["write permission", "  contents: read", "  contents: write"],
  ["identity token", "  contents: read", "  contents: read\n  id-token: write"],
  ["inherited secrets", "    needs: release-inputs", "    needs: release-inputs\n    secrets: inherit"],
  ["publishing token", "${{ github.token }}", "${{ secrets.CARGO_REGISTRY_TOKEN }}"],
  ["dedicated machine", "runs-on: ubuntu-24.04", "runs-on: self-hosted"],
  ["artifact substitution", "candidate_artifact_name: wallet-eudi-candidate-${{ github.run_id }}", "candidate_artifact_name: other"],
  ["unverified candidate", "    needs: release-inputs", "    needs: []"],
  ["credential persistence", "persist-credentials: false", "persist-credentials: true"],
  ["non-main dispatch", "github.ref == 'refs/heads/main'", "github.ref != ''"],
  ["fork dispatch", "github.repository == 'reallyme/wallet'", "github.repository != ''"],
  ["another job", "jobs:", "jobs:\n  extra:\n    runs-on: self-hosted\n    steps:\n      - run: true"],
  ["duplicate trigger", "on:", "on:\n  push:\non:"],
  ["YAML alias", "  workflow_dispatch:", "  workflow_dispatch: &trigger {}\n  push: *trigger"],
]) {
  test(`rejects ${name}`, () => {
    const changed = source.replace(before, after);
    assert.notEqual(changed, source);
    assert.throws(() => verifyManualEudiWorkflow(changed), ManualEudiWorkflowError);
  });
}

test("branches, tags and mismatched immutable pins are rejected", () => {
  const { frameworkCommit } = verifyManualEudiWorkflow(source);
  for (const ref of ["main", "v0.1.0", "a".repeat(39), "G".repeat(40)]) {
    assert.throws(
      () => verifyManualEudiWorkflow(source.replace(`@${frameworkCommit}`, `@${ref}`)),
      ManualEudiWorkflowError,
    );
  }
  const differentCommit = frameworkCommit === "a".repeat(40) ? "b".repeat(40) : "a".repeat(40);
  assert.throws(() => verifyManualEudiWorkflow(source.replace(
    `framework_commit: ${frameworkCommit}`, `framework_commit: ${differentCommit}`,
  )), ManualEudiWorkflowError);
});

test("invalid and oversized input has a fixed domain error", () => {
  for (const input of [undefined, null, {}, "", " ".repeat(16_385)]) {
    assert.throws(() => verifyManualEudiWorkflow(input), (error) =>
      error instanceof ManualEudiWorkflowError && error.code === "invalid_manual_eudi_wallet_workflow");
  }
});

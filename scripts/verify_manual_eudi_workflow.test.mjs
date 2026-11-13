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

test("manual dispatcher selects a published release through its authenticated bootstrap", () => {
  const result = verifyManualEudiWorkflow(source);
  assert.equal(result.frameworkRelease, "v0.3.3");
  assert.deepEqual(verifyManualEudiWorkflow(source.replaceAll("\n", "\r\n")), result);
  assert.doesNotMatch(source, /runs-on: self-hosted|secrets:|\/protected-inputs/u);
  assert.ok(source.indexOf("Authenticate published framework before executing it") <
    source.indexOf("Verify complete framework release manifest"));
  assert.ok(source.indexOf("Verify complete framework release manifest") <
    source.indexOf("Prepare immutable target from existing signed package evidence"));
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
  ["inherited secrets", "  conformance:", "  conformance:\n    secrets: inherit"],
  ["publishing token", "${{ github.token }}", "${{ secrets.CARGO_REGISTRY_TOKEN }}"],
  ["dedicated machine", "runs-on: ubuntu-26.04", "runs-on: self-hosted"],
  ["missing bootstrap", "node scripts/resolve_eudi_framework.mjs", "true"],
  ["unverified candidate", "node scripts/prepare_eudi_release_inputs.mjs", "true"],
  ["missing provenance", "python3 identity-conformance/scripts/verify_wallet_package_preflight.py", "true"],
  ["missing package signatures", "gh attestation verify", "echo"],
  ["wrong source", "ref: ${{ steps.prepare.outputs.target_commit }}", "ref: ${{ github.sha }}"],
  ["wrong workflow identity", "--workflow-revision \"${GITHUB_SHA}\"", "--workflow-revision \"${FRAMEWORK_COMMIT}\""],
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

test("unreviewed default release and mutable checkout substitutions are rejected", () => {
  for (const [before, after] of [["default: v0.3.3", "default: latest"],
    ["ref: ${{ steps.framework.outputs.commit }}", "ref: main"]]) {
    assert.throws(() => verifyManualEudiWorkflow(source.replace(before, after)), ManualEudiWorkflowError);
  }
});

test("invalid and oversized input has a fixed domain error", () => {
  for (const input of [undefined, null, {}, "", " ".repeat(32_769)]) {
    assert.throws(() => verifyManualEudiWorkflow(input), (error) =>
      error instanceof ManualEudiWorkflowError && error.code === "invalid_manual_eudi_wallet_workflow");
  }
});

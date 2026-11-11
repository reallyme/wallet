// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { checkReadinessExecution } from "./check_readiness_execution.mjs";

test("default release validation executes every schema gate in order", () => {
  const calls = [];
  const result = checkReadinessExecution({
    root: "/reviewed",
    run: (_node, args) => {
      calls.push(args);
      return { status: 0 };
    },
  });
  assert.deepEqual(result, { success: true, executedChecks: 4 });
  assert.deepEqual(calls, [
    ["scripts/check_schema_source_lock.mjs"],
    ["scripts/harden-generated-wallet-proto.mjs", "--check-idempotent"],
    ["scripts/check-proto-hardening-concurrency.mjs"],
    ["scripts/check-proto-first-boundaries.mjs"],
  ]);
});

test("only the explicit policy lane delegates execution to its owning CI jobs", () => {
  assert.deepEqual(
    checkReadinessExecution({
      policyOnly: true,
      root: "/reviewed",
      run: () => {
        assert.fail(
          "policy-only validation must not duplicate protobuf execution",
        );
      },
    }),
    { success: true, executedChecks: 0 },
  );
  let calls = 0;
  checkReadinessExecution({
    policyOnly: "true",
    root: "/reviewed",
    run: () => {
      calls += 1;
      return { status: 0 };
    },
  });
  assert.equal(calls, 4);
});

test("failed or unavailable execution stops qualification without leaking backend output", () => {
  for (const outcome of [
    { status: 1, stderr: "untrusted backend text" },
    { status: null },
    undefined,
  ]) {
    let calls = 0;
    const result = checkReadinessExecution({
      root: "/reviewed",
      run: () => {
        calls += 1;
        return outcome;
      },
    });
    assert.deepEqual(result, {
      success: false,
      reason: "schema_source_lock_failed",
      executedChecks: 1,
    });
    assert.equal(calls, 1);
  }
});

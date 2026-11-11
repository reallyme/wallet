// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";

const SCHEMA_CHECKS = Object.freeze([
  {
    arguments: ["scripts/check_schema_source_lock.mjs"],
    reason: "schema_source_lock_failed",
  },
  {
    arguments: [
      "scripts/harden-generated-wallet-proto.mjs",
      "--check-idempotent",
    ],
    reason: "proto_hardening_failed",
  },
  {
    arguments: ["scripts/check-proto-hardening-concurrency.mjs"],
    reason: "proto_hardening_concurrency_failed",
  },
  {
    arguments: ["scripts/check-proto-first-boundaries.mjs"],
    reason: "proto_boundary_validation_failed",
  },
]);

/** Keep complete release validation strict while honoring the explicit CI policy lane. */
export function checkReadinessExecution({
  policyOnly = false,
  root,
  run = spawnSync,
}) {
  if (policyOnly === true) return { success: true, executedChecks: 0 };
  let executedChecks = 0;
  for (const check of SCHEMA_CHECKS) {
    const result = run(process.execPath, check.arguments, {
      cwd: root,
      encoding: "utf8",
    });
    executedChecks += 1;
    if (result?.error !== undefined || result?.status !== 0) {
      // Backend output never becomes an error string; the owning command
      // supplies its detailed diagnostics when run in the protobuf CI lane.
      return { success: false, reason: check.reason, executedChecks };
    }
  }
  return { success: true, executedChecks };
}

#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";

export const MANUAL_EUDI_WORKFLOW_PATH = ".github/workflows/eudi-wallet-conformance.yml";
const MAX_WORKFLOW_CHARACTERS = 16_384;
const REVIEWED_WORKFLOW_SHA256 = "5c5b57262e8fb1fa714ff6233e10647a0b074b06455bed744f2383337a5ed6a3";

export class ManualEudiWorkflowError extends Error {
  constructor() {
    super("invalid_manual_eudi_wallet_workflow");
    this.name = "ManualEudiWorkflowError";
    this.code = "invalid_manual_eudi_wallet_workflow";
  }
}

/** Accept only the reviewed hosted caller, without allowing extra YAML keys. */
export const verifyManualEudiWorkflow = (source) => {
  if (typeof source !== "string" || source.length > MAX_WORKFLOW_CHARACTERS) {
    throw new ManualEudiWorkflowError();
  }
  const executable = source.split(/\r?\n/u)
    .filter((line) => line.trim().length !== 0 && !/^\s*#/u.test(line))
    .map((line) => line.replace(/\s+#.*$/u, "").trimEnd())
    .join("\n");
  const reference = /^    uses: reallyme\/identity-conformance\/\.github\/workflows\/eudi-wallet-conformance\.yml@([0-9a-f]{40})$/mu.exec(executable);
  if (reference === null) throw new ManualEudiWorkflowError();
  // A whole-workflow contract rejects unreviewed triggers, duplicate YAML keys,
  // extra jobs, secrets and command edits. Actionlint validates the YAML and the
  // reusable input contract separately. Pin changes require explicit review.
  const digest = createHash("sha256").update(executable).digest("hex");
  if (digest !== REVIEWED_WORKFLOW_SHA256) throw new ManualEudiWorkflowError();
  return { frameworkCommit: reference[1] };
};

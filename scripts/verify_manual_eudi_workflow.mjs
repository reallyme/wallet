#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";

export const MANUAL_EUDI_WORKFLOW_PATH = ".github/workflows/eudi-wallet-conformance.yml";
const MAX_WORKFLOW_CHARACTERS = 32_768;
const REVIEWED_WORKFLOW_SHA256 = "2267f23463ce26e0d8d5f0956ecd4cc17ddd44f66e06d15e9ac309f7a3040b38";

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
  const reference = /^        default: (v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))$/mu.exec(executable);
  if (reference === null) throw new ManualEudiWorkflowError();
  // A whole-workflow contract rejects unreviewed triggers, duplicate YAML keys,
  // extra jobs, secrets and command edits. Actionlint validates the YAML and the
  // runtime bootstrap separately authenticates the explicitly selected release.
  const digest = createHash("sha256").update(executable).digest("hex");
  if (digest !== REVIEWED_WORKFLOW_SHA256) throw new ManualEudiWorkflowError();
  return { frameworkRelease: reference[1] };
};

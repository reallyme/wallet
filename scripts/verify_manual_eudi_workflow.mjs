#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

export const MANUAL_EUDI_WORKFLOW_PATH = ".github/workflows/eudi-wallet-conformance.yml";
const MAX_WORKFLOW_CHARACTERS = 16_384;
const REUSABLE_WORKFLOW = "reallyme/identity-conformance/.github/workflows/eudi-wallet-conformance.yml";

export class ManualEudiWorkflowError extends Error {
  constructor() {
    super("invalid_manual_eudi_wallet_workflow");
    this.name = "ManualEudiWorkflowError";
    this.code = "invalid_manual_eudi_wallet_workflow";
  }
}

/** Accept only the reviewed manual caller, without permitting extra YAML keys. */
export const verifyManualEudiWorkflow = (source) => {
  if (typeof source !== "string" || source.length > MAX_WORKFLOW_CHARACTERS) {
    throw new ManualEudiWorkflowError();
  }
  const executable = source.split(/\r?\n/u)
    .filter((line) => line.trim().length !== 0 && !/^\s*#/u.test(line))
    .map((line) => line.trimEnd())
    .join("\n");
  const reference = /^    uses: reallyme\/identity-conformance\/\.github\/workflows\/eudi-wallet-conformance\.yml@([0-9a-f]{40})$/mu.exec(executable);
  if (reference === null) throw new ManualEudiWorkflowError();
  const frameworkCommit = reference[1];
  // This narrow contract keeps protected runner inputs out of automatic lanes.
  // Exact keys and indentation also reject aliases, additional jobs, inherited
  // secrets, and a checkout revision different from the reusable workflow pin.
  const expected = [
    "name: EUDI Wallet Conformance",
    "on:",
    "  workflow_dispatch:",
    "permissions:",
    "  contents: read",
    "jobs:",
    "  eudi-wallet-conformance:",
    "    if: github.repository == 'reallyme/wallet' && github.ref == 'refs/heads/main'",
    `    uses: ${REUSABLE_WORKFLOW}@${frameworkCommit}`,
    "    with:",
    `      framework_commit: ${frameworkCommit}`,
    "      release_artifact_path: /protected-inputs/wallet-release",
    "      component_attestation_path: /protected-inputs/wallet-attestation.json",
    "    secrets:",
    "      EUDI_WALLET_DEPLOYMENT_MANIFEST_B64: ${{ secrets.EUDI_WALLET_DEPLOYMENT_MANIFEST_B64 }}",
  ].join("\n");
  if (executable !== expected) throw new ManualEudiWorkflowError();
  return { frameworkCommit };
};

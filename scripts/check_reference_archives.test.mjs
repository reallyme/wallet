// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { validateReferenceArchives } from "../conformance/scripts/validate_eudi_reference_run_archives.mjs";

const KINDS = [
  "suite_export",
  "run_summary",
  "fixture_hash_manifest",
  "environment_manifest",
  "difference_summary",
];
const MANIFEST = "conformance/eudi/reference-run-manifest.json";
const ARCHIVE = "conformance/eudi/runs/example/manifest.json";

function fixture() {
  const root = mkdtempSync(path.join(tmpdir(), "wallet-reference-archives-"));
  const archiveDir = path.dirname(path.join(root, ARCHIVE));
  mkdirSync(archiveDir, { recursive: true });
  const artifacts = KINDS.map((kind) => {
    const name = `${kind}.json`;
    const bytes = Buffer.from(JSON.stringify({ kind }));
    writeFileSync(path.join(archiveDir, name), bytes);
    return {
      kind,
      path: name,
      sha2_256: createHash("sha256").update(bytes).digest("hex"),
    };
  });
  const archive = { id: "example", status: "passed", artifacts };
  const manifest = {
    required_artifact_kinds: KINDS,
    runs: [{
      id: "example",
      status: "passed",
      expected_archive_path: ARCHIVE,
      required_artifacts: KINDS,
    }],
  };
  writeFileSync(path.join(root, ARCHIVE), JSON.stringify(archive));
  writeFileSync(path.join(root, MANIFEST), JSON.stringify(manifest));
  return { root, archiveDir, archive, manifest };
}

async function withFixture(check) {
  const state = fixture();
  try {
    await check(state);
  } finally {
    rmSync(state.root, { recursive: true, force: true });
  }
}

test("accepts an executed run with five matching artifact files", async () => {
  await withFixture(async ({ root }) => {
    await validateReferenceArchives(root, MANIFEST);
  });
});

test("rejects a missing artifact file despite a plausible hash", async () => {
  await withFixture(async ({ root, archiveDir }) => {
    rmSync(path.join(archiveDir, "suite_export.json"));
    await assert.rejects(validateReferenceArchives(root, MANIFEST), /missing-file/u);
  });
});

test("rejects a mutated artifact", async () => {
  await withFixture(async ({ root, archiveDir }) => {
    writeFileSync(path.join(archiveDir, "suite_export.json"), "modified");
    await assert.rejects(validateReferenceArchives(root, MANIFEST), /artifact-digest-mismatch/u);
  });
});

test("rejects nonhex digests, duplicate kinds, and traversal", async () => {
  await withFixture(async ({ root, archive }) => {
    archive.artifacts[0].sha2_256 = "X".repeat(64);
    writeFileSync(path.join(root, ARCHIVE), JSON.stringify(archive));
    await assert.rejects(validateReferenceArchives(root, MANIFEST), /invalid-artifact-entry/u);

    archive.artifacts[0].sha2_256 = createHash("sha256")
      .update(readFileSync(path.join(root, path.dirname(ARCHIVE), "suite_export.json")))
      .digest("hex");
    archive.artifacts[1].kind = archive.artifacts[0].kind;
    writeFileSync(path.join(root, ARCHIVE), JSON.stringify(archive));
    await assert.rejects(validateReferenceArchives(root, MANIFEST), /invalid-artifact-entry/u);

    archive.artifacts[1].kind = KINDS[1];
    archive.artifacts[0].path = "../outside.json";
    writeFileSync(path.join(root, ARCHIVE), JSON.stringify(archive));
    await assert.rejects(validateReferenceArchives(root, MANIFEST), /unsafe-path/u);
  });
});

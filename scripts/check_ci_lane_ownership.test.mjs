// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = fileURLToPath(new URL("..", import.meta.url));
const checker = resolve(root, "scripts/check_ci_lane_ownership.mjs");

test("public CI rejects private evidence dependencies in every workflow lane", () => {
  const snapshot = mkdtempSync(resolve(tmpdir(), "wallet-ci-contract-"));
  try {
    mkdirSync(resolve(snapshot, ".github/workflows"), { recursive: true });
    mkdirSync(resolve(snapshot, "scripts"));
    const workflows = readdirSync(resolve(root, ".github/workflows"));
    for (const name of workflows) {
      writeFileSync(
        resolve(snapshot, ".github/workflows", name),
        readFileSync(resolve(root, ".github/workflows", name)),
      );
    }
    writeFileSync(
      resolve(snapshot, "scripts/check_security_gates.sh"),
      readFileSync(resolve(root, "scripts/check_security_gates.sh")),
    );
    const run = () => spawnSync(process.execPath, [checker], {
      cwd: snapshot,
      encoding: "utf8",
    });
    assert.equal(run().status, 0);
    for (const name of workflows) {
      const path = resolve(snapshot, ".github/workflows", name);
      const source = readFileSync(path, "utf8");
      for (const dependency of [
        "repository: reallyme/identity-conformance",
        "repository: REALLYME/IDENTITY-TAXONOMY",
        "run: node scripts/generate_wallet_taxonomy_evidence.mjs --check",
        "repository: reallyme/zk",
        "repository: reallyme/ssi",
      ]) {
        writeFileSync(path, `${source}\n${dependency}\n`);
        const result = run();
        assert.equal(result.status, 1);
        assert.match(result.stderr, /public CI must/u);
      }
      writeFileSync(path, source);
    }
  } finally {
    rmSync(snapshot, { recursive: true, force: true });
  }
});

test("registry provenance needs no ZK checkout and retained source pins must still match", () => {
  const snapshot = mkdtempSync(resolve(tmpdir(), "wallet-release-ci-contract-"));
  try {
    mkdirSync(resolve(snapshot, ".github/workflows"), { recursive: true });
    mkdirSync(resolve(snapshot, "scripts"));
    for (const path of [
      ".github/workflows/crates-package-preflight.yml",
      ".github/workflows/crates-release.yml",
      "scripts/sibling-source-provenance.json",
    ]) {
      writeFileSync(resolve(snapshot, path), readFileSync(resolve(root, path)));
    }
    const run = () => spawnSync(process.execPath, [
      resolve(root, "scripts/check_crates_release_workflows.mjs"),
    ], { cwd: snapshot, encoding: "utf8" });
    assert.equal(run().status, 0);
    const provenance = JSON.parse(readFileSync(
      resolve(snapshot, "scripts/sibling-source-provenance.json"), "utf8",
    ));
    const dependency = provenance.repositories.find((row) => row.directory === "openid4vp");
    assert.ok(dependency);
    for (const name of ["crates-package-preflight.yml", "crates-release.yml"]) {
      const path = resolve(snapshot, ".github/workflows", name);
      const source = readFileSync(path, "utf8");
      const checkout = /uses: (actions\/checkout@[0-9a-f]{40})/u.exec(source)?.[1];
      assert.ok(checkout);
      const step = [
        "      - name: Checkout reviewed protocol source",
        `        uses: ${checkout}`,
        "        with:",
        "          repository: reallyme/openid4vp",
        `          ref: ${dependency.commit}`,
        "          persist-credentials: false",
        "",
      ].join("\n");
      writeFileSync(path, `${source}\n${step}`);
      assert.equal(run().status, 0);
      writeFileSync(path, `${source}\n${step.replace(
        `ref: ${dependency.commit}`, `ref: ${"0".repeat(40)}`,
      )}`);
      const result = run();
      assert.equal(result.status, 1);
      assert.match(result.stderr, /source checkout does not pin openid4vp/u);
      writeFileSync(path, source);
    }
  } finally {
    rmSync(snapshot, { recursive: true, force: true });
  }
});

// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("./prepare_eudi_release_inputs.mjs", import.meta.url));
const policy = JSON.parse(readFileSync(new URL("../conformance/features/wallet-package-policy-v1.json", import.meta.url), "utf8"));
const sha = "a".repeat(40);
const frameworkSha = "b".repeat(40);

const fixture = (scenario = "success") => {
  const root = mkdtempSync(join(tmpdir(), "wallet-eudi-input-test-"));
  try {
    const framework = join(root, "framework");
    mkdirSync(join(framework, "upstream/eudi"), { recursive: true });
    mkdirSync(join(framework, "references"));
    for (const path of ["upstream/eudi/sources.lock.json", "upstream/eudi/legal-sources.lock.json", "references/eudi-publications.lock.json"]) {
      writeFileSync(join(framework, path), "{}\n");
    }
    const archives = policy.authorized_public_packages.map((name) => {
      const bytes = Buffer.from(`fixture archive:${name}`);
      return { file: `${name}-${policy.release_version}.crate`, size: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
    }).sort((a, b) => a.file.localeCompare(b.file));
    const manifest = { schema: "reallyme.wallet.crates_preflight.v3", crates: archives,
      prerequisites: { fuzz: 1, protobuf_ci: 2, rust_ci: 3 }, repository: "reallyme/wallet",
      workflow: "crates-package-preflight.yml", run_id: 42, run_attempt: 1, release_sha: sha, version: policy.release_version };
    const calls = join(root, "calls.json");
    const preload = join(root, "preload.mjs");
    writeFileSync(preload, `
import cp from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
const scenario = ${JSON.stringify(scenario)};
const manifest = ${JSON.stringify(manifest)};
const sha = ${JSON.stringify(sha)};
const framework = ${JSON.stringify(frameworkSha)};
const calls = [];
const ok = {status:0,stdout:"",stderr:""};
const answer = (value) => ({...ok,stdout:JSON.stringify(value)});
cp.spawnSync = (program,args) => {
  calls.push([program,...args]);
  writeFileSync(${JSON.stringify(calls)},JSON.stringify(calls));
  if(program === "git") return {...ok,stdout: args.includes("rev-parse") ? framework : scenario === "dirty-framework" ? " M changed" : ""};
  if(program === "tar") {writeFileSync(args[1],"fixture bundle"); return ok;}
  if(program === "python3") return ok;
  if(program !== "gh") return {...ok,status:99};
  if(args[0] === "attestation") return scenario === "signature-failure" ? {...ok,status:1} : ok;
  if(args[0] === "release") {
    const directory=args[args.indexOf("--dir")+1];
    for(const item of manifest.crates) {
      const name=item.file.slice(0,-"-${policy.release_version}.crate".length);
      writeFileSync(join(directory,item.file),scenario === "tampered-archive" ? "tampered" : "fixture archive:"+name);
    }
    writeFileSync(join(directory,"crates-preflight.json"),JSON.stringify(manifest));
    return ok;
  }
  const endpoint=args[1];
  if(endpoint.includes("releases/tags")) return answer({id:1,tag_name:"reallyme-wallet-v${policy.release_version}",draft:scenario==="draft-release",prerelease:false});
  if(endpoint.includes("actions/workflows")) return answer({id:5});
  if(endpoint.includes("/jobs?")) return answer({total_count:1,jobs:[{id:9,run_id:42,run_attempt:1,head_sha:sha,name:"Review crates.io packages",status:"completed",conclusion:"success",steps:["Check formatting","Clippy","Test all features","Check protobuf boundaries and generated source","Check dependency policy","Security advisory audit","Inspect normalized crate tarballs and dry-run publication","Check Identity Wasm participant lane"].map((name,index)=>({name,number:index+1,status:"completed",conclusion:scenario==="failed-step" && index===0 ? "failure":"success"}))}]});
  if(endpoint.includes("actions/runs")) return answer({id:42,workflow_id:5,event:"workflow_dispatch",head_branch:"main",head_sha:scenario==="wrong-preflight-commit" ? "f".repeat(40):sha,status:"completed",conclusion:"success",run_attempt:1,path:".github/workflows/crates-package-preflight.yml"});
  if(endpoint.includes("contents/Cargo.lock")) return answer({encoding:"base64",content:Buffer.from("fixture cargo lock").toString("base64")+(scenario==="invalid-lock-encoding" ? "!":""),size:18});
  return {...ok,status:99};
};
globalThis.fetch = async (url) => {
  const target=String(url);
  if(target.startsWith("https://api.github.com/")) return new Response(JSON.stringify({ref:"refs/tags/reallyme-wallet-v${policy.release_version}",object:{type:"commit",sha:scenario==="wrong-tag" ? "f".repeat(40):sha}}));
  const name=target.split("/").at(-2);
  const archive=manifest.crates.find(item=>item.file===name+"-${policy.release_version}.crate");
  return new Response(JSON.stringify({version:{crate:name,num:"${policy.release_version}",yanked:scenario==="yanked",checksum:scenario==="registry-mismatch" ? "0".repeat(64):archive.sha256}}));
};
syncBuiltinESMExports();
`);
    const output = join(root, "inputs");
    const completed = spawnSync(process.execPath, ["--import", pathToFileURL(preload).href, script], {
      encoding: "utf8", timeout: 15_000, env: { ...process.env,
        GITHUB_REPOSITORY: "reallyme/wallet", GH_TOKEN: "fixture-only-not-a-credential",
        RUNNER_TEMP: root, FRAMEWORK_COMMIT: frameworkSha, EUDI_FRAMEWORK_PATH: framework, EUDI_INPUT_DIRECTORY: output,
      },
    });
    assert.equal(completed.error, undefined);
    return { ...completed, calls: existsSync(calls) ? JSON.parse(readFileSync(calls, "utf8")) : [],
      deployment: existsSync(join(output, "deployment.json")) ? JSON.parse(readFileSync(join(output, "deployment.json"), "utf8")) : undefined,
      attestation: existsSync(join(output, "wallet-attestation.json")) ? JSON.parse(readFileSync(join(output, "wallet-attestation.json"), "utf8")) : undefined };
  } finally { rmSync(root, { recursive: true, force: true }); }
};

test("hosted input preparation verifies all 18 signatures before binding real CI evidence", () => {
  const result = fixture();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.calls.filter((call) => call[0] === "gh" && call[1] === "attestation").length, 18);
  assert.equal(result.deployment.component.commit, sha);
  assert.equal(result.attestation.checks.length, 7);
  assert.equal(result.attestation.release.version, policy.release_version);
  assert.equal(result.calls.some((call) => call[0] === "cargo"), false);
  assert.ok(result.calls.findIndex((call) => call[1] === "attestation") < result.calls.findIndex((call) => call[0] === "tar"));
});

for (const scenario of ["draft-release", "dirty-framework", "tampered-archive", "signature-failure",
  "wrong-preflight-commit", "failed-step", "wrong-tag", "yanked", "registry-mismatch", "invalid-lock-encoding"]) {
  test(`${scenario} fails before creating deployment evidence`, () => {
    const result = fixture(scenario);
    assert.equal(result.status, 1, result.stderr);
    assert.equal(result.deployment, undefined);
    assert.equal(result.attestation, undefined);
    assert.equal(result.calls.some((call) => call[0] === "tar"), false);
    assert.doesNotMatch(result.stderr, /fixture-only-not-a-credential/u);
  });
}

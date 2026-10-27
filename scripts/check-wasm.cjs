// Run after make build and scripts/make-demo.go. This is an engine smoke test,
// not a browser automation substitute or a genuine hardware success fixture.
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
globalThis.crypto = require("node:crypto").webcrypto;

(async () => {
  const dir = process.argv[2];
  if (!dir) throw new Error("Usage: node scripts/check-wasm.cjs <demo-directory>");
  vm.runInThisContext(fs.readFileSync("web/static/wasm_exec.js", "utf8"));
  const go = new Go();
  const { instance } = await WebAssembly.instantiate(fs.readFileSync("web/static/verifier.wasm"), go.importObject);
  go.run(instance).catch(error => { throw error; });
  const read = name => new Uint8Array(fs.readFileSync(path.join(dir, name)));
  const options = { expected_app: fs.readFileSync(path.join(dir,"expected-app.txt"),"utf8") };
  const report = JSON.parse(tokhiveVerify(JSON.stringify(options), read("receipt.cbor"), null, read("response.raw"), read("job-spec.cbor"), read("request.raw")));
  assert.equal(report.status, "failed");
  assert.equal(report.verified, false);
  assert.equal(report.checks.find(check => check.id === "signature").status, "passed");
  assert.equal(report.checks.find(check => check.id === "hardware").status, "failed");
  assert.equal(report.checks.find(check => check.id === "request").status, "passed");
  assert.equal(report.checks.find(check => check.id === "response").status, "passed");
  assert.equal(report.bound_claims, undefined);
  const native = spawnSync("./bin/tokhive-verify", ["verify","--json","--expected-app",options.expected_app,"--response",path.join(dir,"response.raw"),"--job-spec",path.join(dir,"job-spec.cbor"),"--request",path.join(dir,"request.raw"),path.join(dir,"receipt.cbor")],{encoding:"utf8"});
  assert.equal(native.status, 1, native.stderr);
  const nativeReport = JSON.parse(native.stdout);
  delete nativeReport.verified_at; delete report.verified_at;
  assert.deepEqual(report, nativeReport);
  const broken = JSON.parse(tokhiveVerify("{}", new Uint8Array([0]), null, null, null, null));
  assert.equal(broken.status, "failed");
  console.log("Native/WASM reports agree; forged hardware, malformed receipts and content scope checks passed.");
  process.exit(0);
})().catch(error => { console.error(error); process.exit(1); });

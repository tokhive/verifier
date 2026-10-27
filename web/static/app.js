"use strict";

const $ = id => document.getElementById(id);
const form = $("verify-form");
const fileLimits = { receipt: 2, evidence: 4, response: 64, "job-spec": 2, request: 16 };
let worker;
let engineReady = false;
let busy = false;
let downloadURL;
let timeout;
let bundle;
let apiOrigin;
let lookupContext;

const mode = () => form.elements.mode.value;
function updateMode() {
  $("lookup-fields").hidden = mode() !== "lookup";
  $("receipt-zone").hidden = mode() !== "file";
  $("receipt").required = mode() === "file";
}
document.querySelectorAll('input[name="mode"]').forEach(input => input.addEventListener("change", updateMode));
for (const id of ["request-id", "api-key"]) $(id).addEventListener("input", () => {
  bundle = undefined; $("attempt-picker").hidden = true; $("lookup-status").textContent = "";
});

async function lookupAttempt() {
  if (!apiOrigin) throw new Error("Request-ID mode requires the local verifier server. Run tokhive-verify serve.");
  const requestID = $("request-id").value.trim();
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(requestID)) throw new Error("Enter a valid request ID.");
  if (!bundle) {
    $("lookup-status").textContent = "Fetching your execution evidence…";
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 25000);
    try {
      const response = await fetch("/api/lookup", {
        method: "POST", headers: { "Content-Type": "application/json", "X-TokHive-Verifier": "1" },
        body: JSON.stringify({ request_id: requestID, api_key: $("api-key").value }), signal: controller.signal,
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || `Evidence lookup failed (${response.status}).`);
      bundle = result;
    } finally { clearTimeout(timer); }
    $("api-key").value = "";
    $("attempt-id").replaceChildren();
    const empty = new Option("Choose an execution attempt", ""); $("attempt-id").append(empty);
    for (const attempt of bundle.attempts) $("attempt-id").append(new Option(attempt.id, attempt.id));
    $("attempt-picker").hidden = bundle.attempts.length <= 1;
    if (bundle.attempts.length === 1) $("attempt-id").value = bundle.attempts[0].id;
    $("lookup-status").textContent = `Downloaded ${bundle.attempts.length} execution receipt(s). Evidence still requires local verification.`;
  }
  const attempt = bundle.attempts.find(item => item.id === $("attempt-id").value);
  if (!attempt) throw new Error("Choose an execution attempt, then verify again.");
  lookupContext = { request_id: requestID, attempt_id: attempt.id, api_origin: apiOrigin };
  return attempt;
}

function decodeBytes(base64) {
  if (!base64) return null;
  const raw = atob(base64); const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out.buffer;
}

function mergeEvidence(local, downloaded, name) {
  if (local && downloaded) {
    const a = new Uint8Array(local), b = new Uint8Array(downloaded);
    if (a.length !== b.length || a.some((value, i) => value !== b[i])) throw new Error(`Local ${name} conflicts with the downloaded evidence.`);
  }
  return local || downloaded;
}

function clearReport() {
  $("report").hidden = true;
  $("empty-state").hidden = false;
  $("form-error").hidden = true;
  if (downloadURL) { URL.revokeObjectURL(downloadURL); downloadURL = undefined; }
  $("download-report").removeAttribute("href");
}

function setBusy(value) {
  busy = value;
  $("input-fields").disabled = value;
  $("reset-button").disabled = value;
  $("verify-button").disabled = value || !engineReady;
  $("verify-button").textContent = value ? "Checking evidence…" : engineReady ? "Verify receipt →" : "Engine unavailable";
  form.setAttribute("aria-busy", String(value));
}

function fail(message) {
  clearTimeout(timeout);
  setBusy(false);
  $("form-error").textContent = message;
  $("form-error").hidden = false;
}

function boot() {
  worker = new Worker("worker.js");
  worker.onmessage = ({ data }) => {
    if (data.type === "ready") {
      engineReady = true;
      $("engine-status").className = "engine-status ready";
      $("engine-status").textContent = "● Engine ready · same Go core as the CLI · files stay local";
      setBusy(false);
    } else if (data.type === "report") {
      clearTimeout(timeout); setBusy(false);
      if (lookupContext) {
        data.report.lookup = lookupContext;
        data.report.notes.push("Request-ID to execution-ID mapping was supplied by the buyer API; the buyer request ID is not itself signed by the TEE.");
      }
      render(data.report);
    } else if (data.type === "error") {
      fail(data.message);
    }
  };
  worker.onerror = () => {
    engineReady = false;
    $("engine-status").className = "engine-status error";
    $("engine-status").textContent = "Engine failed to load. Run make build and reload this page.";
    fail("Cannot start the local WebAssembly engine. Check that the built assets are available.");
  };
}

Object.keys(fileLimits).forEach(id => {
  $(id).addEventListener("change", () => {
    const file = $(id).files[0];
    $(`${id}-name`).textContent = file ? `${file.name} · ${(file.size / 1024).toFixed(1)} KiB` : "No file selected";
  });
});
form.addEventListener("input", () => { if (!busy) clearReport(); });
form.addEventListener("change", () => { if (!busy) clearReport(); });
form.addEventListener("reset", () => {
  clearReport();
  bundle = undefined; lookupContext = undefined; $("attempt-picker").hidden = true; $("lookup-status").textContent = "";
  setTimeout(updateMode, 0);
  Object.keys(fileLimits).forEach(id => { $(`${id}-name`).textContent = "No file selected"; });
});

form.addEventListener("submit", async event => {
  event.preventDefault();
  if (!engineReady || busy) return;
  clearReport();
  lookupContext = undefined;
  try {
    const maxAge = Number($("max-age").value);
    if (!Number.isSafeInteger(maxAge) || maxAge < 0) throw new Error("Maximum age must be a non-negative whole number.");
    const files = {};
    for (const [id, limit] of Object.entries(fileLimits)) {
      const file = $(id).files[0];
      if (file && file.size > limit * 1024 * 1024) throw new Error(`${file.name} exceeds the ${limit} MiB limit.`);
      files[id] = file || null;
    }
    if (mode() === "file" && !files.receipt) throw new Error("Choose a receipt file first.");
    setBusy(true);
    const attempt = mode() === "lookup" ? await lookupAttempt() : null;
    const read = async file => file ? file.arrayBuffer() : null;
    let [receipt, evidence, response, jobSpec, request] = await Promise.all([read(mode() === "file" ? files.receipt : null), read(files.evidence), read(files.response), read(files["job-spec"]), read(files.request)]);
    if (attempt) {
      receipt = decodeBytes(attempt.receipt);
      evidence = mergeEvidence(evidence, decodeBytes(attempt.evidence), "hardware evidence");
      jobSpec = mergeEvidence(jobSpec, decodeBytes(attempt.job_spec), "task specification");
    }
    const options = {
      expected_app: $("expected-app").value.trim(),
      expected_policy: $("expected-policy").value.trim(),
      expected_host: $("expected-host").value.trim(),
      expected_job_id: $("expected-job-id").value.trim() || (attempt ? attempt.id : ""),
      max_age_seconds: maxAge,
    };
    worker.postMessage({ options, receipt, evidence, response, jobSpec, request }, [receipt, evidence, response, jobSpec, request].filter(Boolean));
    timeout = setTimeout(() => {
      worker.terminate(); engineReady = false;
      fail("Verification timed out. The engine was stopped; reload the page to try again.");
      $("engine-status").textContent = "Engine stopped after timeout. Reload to restart.";
    }, 60000);
  } catch (error) { fail(error.message); }
});

function addMetadata(target, pairs) {
  target.replaceChildren();
  for (const [label, value] of pairs) {
    if (value === undefined || value === "") continue;
    const row = document.createElement("div");
    const dt = document.createElement("dt"); dt.textContent = label;
    const dd = document.createElement("dd"); dd.textContent = String(value);
    row.append(dt, dd); target.append(row);
  }
}

function render(report) {
  $("empty-state").hidden = true; $("report").hidden = false;
  const titles = { verified: "Receipt verified.", incomplete: "More evidence needed.", failed: "Verification failed." };
  const descriptions = {
    verified: "The signature, hardware evidence and trusted application checks passed. Content comparison is shown separately below.",
    incomplete: "No failed checks, but a required trust or content check is missing. See the steps below.",
    failed: "At least one check failed. This result does not establish trusted execution or content integrity.",
  };
  $("report-banner").className = `report-banner ${report.status}`;
  $("report-status").textContent = report.status.toUpperCase();
  $("report-heading").textContent = titles[report.status];
  $("report-description").textContent = descriptions[report.status];
  $("receipt-scope").textContent = report.verified ? "Verified" : "Not verified";
  $("request-scope").textContent = report.request_verified ? "Bytes match" : "Not verified";
  $("response-scope").textContent = report.response_verified ? "Bytes match" : "Not verified";
  $("checks").replaceChildren();
  for (const check of report.checks) {
    const li = document.createElement("li"); li.className = `check ${check.status}`;
    const header = document.createElement("div"); header.className = "check-header";
    const symbol = document.createElement("span"); symbol.className = "check-symbol"; symbol.setAttribute("aria-hidden", "true"); symbol.textContent = { passed: "✓", failed: "×", skipped: "–" }[check.status];
    const title = document.createElement("h4"); title.textContent = `${check.label} · ${check.status}`;
    const message = document.createElement("p"); message.textContent = check.message;
    header.append(symbol, title); li.append(header, message); $("checks").append(li);
  }
  $("metadata-section").hidden = !report.receipt;
  if (report.receipt) addMetadata($("metadata"), Object.entries(report.receipt).map(([key, value]) => [key.replaceAll("_", " "), value]));
  $("claims-section").hidden = !report.bound_claims || !Object.values(report.bound_claims).some(Boolean);
  if (report.bound_claims) addMetadata($("claims"), Object.entries(report.bound_claims).map(([key, value]) => [key.replaceAll("_", " "), value]));
  $("notes").replaceChildren();
  for (const note of report.notes) { const li = document.createElement("li"); li.textContent = note; $("notes").append(li); }
  downloadURL = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2) + "\n"], { type: "application/json" }));
  $("download-report").href = downloadURL;
}

boot();
fetch("/api/config").then(response => response.ok ? response.json() : null).then(config => {
  if (config?.api_base_url) { apiOrigin = config.api_base_url; $("api-origin").textContent = apiOrigin; }
}).catch(() => {});

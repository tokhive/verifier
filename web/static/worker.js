/* The verification engine runs off the UI thread. Nothing is uploaded. */
importScripts("wasm_exec.js");

async function boot() {
  const go = new Go();
  const response = await fetch("verifier.wasm");
  if (!response.ok) throw new Error(`Engine download failed (${response.status}). Run make build.`);
  const bytes = await response.arrayBuffer();
  const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
  go.run(instance).catch(error => postMessage({ type: "error", message: error.message }));
  // Go installs the synchronous verification entry point before yielding.
  if (typeof tokhiveVerify !== "function") throw new Error("Verification engine did not initialize.");
  postMessage({ type: "ready" });
}

const ready = boot().catch(error => { postMessage({ type: "error", message: error.message }); throw error; });
onmessage = async ({ data }) => {
  try {
    await ready;
    const asBytes = buffer => buffer === null ? null : new Uint8Array(buffer);
    const report = JSON.parse(tokhiveVerify(JSON.stringify(data.options), asBytes(data.receipt), asBytes(data.evidence), asBytes(data.response), asBytes(data.jobSpec), asBytes(data.request)));
    if (report.engine_error) throw new Error(report.engine_error);
    postMessage({ type: "report", report });
  } catch (error) {
    postMessage({ type: "error", message: error.message });
  }
};

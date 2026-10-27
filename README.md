# TokHive Verifier

A standalone execution receipt verifier with CLI and web interfaces. Both use the same Go verification core. The web interface runs verification in a browser Web Worker through WebAssembly, without uploading local receipts, requests, or responses.

## Features

- Verify canonical CBOR encoding, TEE receipt signatures, and signing-key bindings.
- Reuse the `tokhive/tee` verification library to check AWS SEV-SNP / NitroTPM evidence chains, hardware policy, and the expected application identity. Simulated platforms are rejected.
- Check a user-supplied application hash and optional expectations for the policy hash, upstream host, execution ID, and maximum receipt age.
- Support both inline hardware evidence and separate evidence files for hash-only receipts.
- Optionally compare the raw response's execution-bound hash and byte count. Extract model and usage declarations from supported JSON and SSE responses.
- Optionally verify the chain from task specification to request-body hash to raw request, establishing the receipt's indirect binding to the requested model and other input content.
- Accept receipt files or download evidence by request ID using a buyer API key. Requests with multiple execution attempts require an explicit selection; receipts are verified individually.
- Report individual checks, signed execution fields, and the scope of content comparisons. Export JSON reports and return documented CLI exit codes.

## Build

Requires Go 1.27.3+ and Make. Node.js is needed only for the optional WASM runtime check. Development currently uses the sibling `../tee` checkout:

```text
tokhive/
├── tee/
└── verifier/
```

From the `verifier` directory:

```bash
make build
./bin/tokhive-verify --help
```

`make build` generates `web/static/verifier.wasm` and copies the official Go runtime, then embeds the web assets in the CLI. The resulting binary can be distributed on its own; users do not need Go installed. Generated build assets are excluded from version control. The WASM engine is currently about 38 MiB because it reuses the TEE shared library. It loads on the first visit; enable gzip or Brotli when hosting the static assets.

## CLI: verify a file

Obtain the full expected application identity from an independently trusted release source. Do not use the receipt's own claimed hash as the trust anchor.

```bash
./bin/tokhive-verify verify \
  --expected-app "snp-app:<64-character-lowercase-hex-release-hash>" \
  --expected-host api.anthropic.com \
  --response response.raw \
  receipt.cbor
```

To compare the input as well:

```bash
./bin/tokhive-verify verify \
  --expected-app "$TOKHIVE_EXPECTED_APP" \
  --job-spec job-spec.cbor \
  --request request.raw \
  --response response.raw \
  --json \
  receipt.cbor
```

For a hash-only receipt, add `--evidence evidence.bin`. See `verify --help` for other options. Place all options before the receipt path.

## CLI: verify by request ID

Set your buyer API key in the environment so it does not appear in command-line arguments or process listings:

```bash
# Set TOKHIVE_API_KEY to your own buyer API key before running this command.
./bin/tokhive-verify verify \
  --request-id "$TOKHIVE_REQUEST_ID" \
  --expected-app "$TOKHIVE_EXPECTED_APP" \
  --json
```

The default endpoint is `https://api.tokhive.ai/v1/verification/requests/{id}`. Use `--api-base-url` to select another API origin. HTTPS is required, with loopback HTTP allowed for local development. Use `--api-key-env` to select a different environment variable for the key.

If the request has multiple receipts, add `--attempt-id <execution-id>`. Without a selection, the CLI lists the available IDs and exits; it does not silently choose the successful attempt.

You can also supply local `--request`, `--response`, `--job-spec`, or `--evidence` files. Conflicting local and downloaded evidence is rejected.

Hive implements buyer authentication and request ownership checks for the public endpoint. See [API.md](API.md) for the protocol. This flow does not use administrator endpoints or administrator sessions. The endpoint must be deployed with Hive before production request lookups are available. Missing evidence or insufficient permissions never fall back to sample data.

## Web interface

```bash
./bin/tokhive-verify serve
# To connect to a local Hive instance:
./bin/tokhive-verify serve --api-base-url http://127.0.0.1:5180
```

Open the printed URL, `http://127.0.0.1:8787`. Choose **Receipt file** or **Request ID**, enter a trusted application identity, and start verification.

- **File mode:** files stay in the browser. Verification can run offline after the engine loads.
- **Request ID mode:** the buyer key is used only to download evidence from the configured Hive origin. It is not persisted, placed in URLs, or included in reports. The key input is cleared after a successful download. The local server proxies only this fixed evidence source; it does not accept arbitrary destination URLs.
- Raw request and response files are never uploaded to the local server or Hive.
- Requests with multiple receipts display an attempt selector. Each receipt is verified separately. Results distinguish passed, failed, and skipped checks, with instructions for supplying missing evidence.
- Export a JSON report for inspection or recordkeeping. Changing an input clears the previous report so an old result cannot be mistaken for a new one.

The static web assets can also be hosted separately, and file mode will still work. The web request-ID flow currently uses the local bridge provided by `serve`, avoiding cross-origin configuration and arbitrary credential destinations. Production hosting of that flow requires an equally restricted bridge under an explicitly trusted origin. Do not directly expose the current loopback-only server as a public service.

## Understanding results

| Result | Meaning | CLI exit code |
|---|---|---:|
| `verified` | All required trust checks and comparisons for supplied content passed | 0 |
| `failed` | At least one check failed | 1 |
| Usage, I/O, or lookup error | Invalid arguments, unreadable files, or failed evidence downloads | 2 |
| `incomplete` | No checks failed, but a required application expectation, hardware evidence, or task specification is missing | 3 |

`verified` does not mean all content was compared. Inspect the separate `request_verified` and `response_verified` fields. Content that was not supplied is never marked as verified. A failed or truncated execution can still produce an authentic signed receipt; the report shows its completion state and HTTP status separately.

Model names and token counts are declarations inside signature-bound content. Matching content hashes establish that those declarations have not changed. The verifier does not independently identify the model the vendor actually ran or recount tokens. Unsupported content formats can still be compared byte for byte, but their declaration fields are not extracted. Input and output token counts are returned as decimal strings to preserve large-integer precision in JavaScript.

## Current evidence scope

- Only AWS SEV-SNP receipts are supported. Hardware certificates are checked at the current time; expired chains are rejected. Archival verification with trusted historical timestamps is not supported yet.
- The mapping from buyer request ID to execution ID comes from the authenticated Hive API. The buyer request ID itself is not a TEE-signed field.
- The API does not publish a trusted release manifest. Users must obtain the expected application hash from a trusted release source.
- Hive currently stores receipts and task hashes, not complete task specifications or raw upstream bodies. Downloaded receipts can be verified, but comparing the input requires a separately obtained specification and raw request. Billing metadata cannot replace that evidence.
- A response file must contain the exact upstream body relayed by the TEE. Hive protocol translation, compression or decompression, and history recovery can change request or response bytes. Client-visible bodies may therefore differ from signed content. Reserializing JSON is not a valid way to force a match.
- File limits: receipt and job specification, 2 MiB each; evidence, 4 MiB; request, 16 MiB; response, 64 MiB.

## Validation

```bash
make test
make build
go run scripts/make-demo.go /tmp/tokhive-verifier-demo
node scripts/check-wasm.cjs /tmp/tokhive-verifier-demo
```

The demo is signed with a software key and deliberately lacks genuine hardware evidence. Its expected result is a hardware verification failure; it is not a successful verification example. Unit tests use a private test seam to exercise successful orchestration. The public verification API always calls the real hardware verification library and has no option to bypass it. Acceptance testing of a successful production receipt still requires valid, unexpired hardware evidence and a trusted application identity.

## Project layout

```text
verify.go, content.go     Shared verification core and content binding
lookup/                  Buyer evidence lookup client
cmd/tokhive-verify/       CLI entry point
cmd/wasm/                WebAssembly entry point for the same core
internal/cli/            CLI commands, local web server, and restricted lookup bridge
web/static/              Web interface, Web Worker, and generated WASM assets
scripts/                 Engine consistency checks and rejection-demo generator
```

// Package cli implements the native command UI. Verification is shared with WASM.
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/tokhive/verifier"
	"github.com/tokhive/verifier/lookup"
	"github.com/tokhive/verifier/web"
)

const usage = `TokHive Verifier

  tokhive-verify verify [options] receipt.cbor
  tokhive-verify verify --request-id <id> [options]
  tokhive-verify serve [--listen 127.0.0.1:8787]

Verify canonical-CBOR execution receipts offline. Web mode serves a static UI;
all file processing and verification happen in the browser using WebAssembly.
Use "verify --help" for verification options. Flags precede the receipt path.

Exit codes: 0 verified, 1 verification failed, 2 usage/I/O error, 3 incomplete.
`

func Run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(out, usage)
		return 0
	}
	switch args[0] {
	case "verify":
		return runVerify(args[1:], out, errOut)
	case "serve":
		return runServe(args[1:], out, errOut)
	case "version", "--version":
		fmt.Fprintln(out, "tokhive-verify 0.1.0")
		return 0
	default:
		fmt.Fprintln(errOut, "Unknown command:", args[0])
		fmt.Fprint(errOut, usage)
		return 2
	}
}

func runVerify(args []string, out, errOut io.Writer) int {
	f := flag.NewFlagSet("verify", flag.ContinueOnError)
	f.SetOutput(errOut)
	var o verifier.Options
	f.StringVar(&o.ExpectedApp, "expected-app", "", "independently trusted snp-app:<64 lowercase hex> identity (required for verified status)")
	f.StringVar(&o.ExpectedPolicy, "expected-policy", "", "expected policy SHA-256 (64 lowercase hex)")
	f.StringVar(&o.ExpectedHost, "expected-host", "", "expected upstream hostname")
	f.StringVar(&o.ExpectedJobID, "expected-job-id", "", "expected receipt execution ID (32 lowercase hex)")
	f.Int64Var(&o.MaxAgeSeconds, "max-age", 0, "maximum receipt age in seconds; 0 disables age limit")
	evidence := f.String("evidence", "", "matching evidence file for a hash-only receipt")
	response := f.String("response", "", "exact raw upstream response body to compare")
	spec := f.String("job-spec", "", "canonical-CBOR task specification bound by the receipt")
	request := f.String("request", "", "exact raw request body; requires --job-spec")
	asJSON := f.Bool("json", false, "emit a structured JSON report")
	requestID := f.String("request-id", "", "fetch evidence for your request using a buyer API key")
	attemptID := f.String("attempt-id", "", "select an execution attempt when a request has several receipts")
	apiBase := f.String("api-base-url", "https://api.tokhive.ai", "buyer verification API origin")
	keyEnv := f.String("api-key-env", "TOKHIVE_API_KEY", "environment variable containing your buyer API key")
	if err := f.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if (*requestID == "" && f.NArg() != 1) || (*requestID != "" && f.NArg() != 0) || (*attemptID != "" && *requestID == "") {
		fmt.Fprintln(errOut, "Provide either one receipt file or --request-id. Flags must precede the receipt path.")
		return 2
	}
	in := verifier.Input{Options: o}
	var err error
	if *requestID == "" {
		if in.Receipt, err = readFile(f.Arg(0), verifier.MaxReceiptBytes); err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
	}
	if *evidence != "" {
		if in.Evidence, err = readFile(*evidence, verifier.MaxEvidenceBytes); err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
	}
	if *response != "" {
		in.ResponseProvided = true
		if in.Response, err = readFile(*response, verifier.MaxResponseBytes); err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
	}
	if *spec != "" {
		if in.JobSpec, err = readFile(*spec, verifier.MaxJobSpecBytes); err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
	}
	if *request != "" {
		in.RequestProvided = true
		if in.Request, err = readFile(*request, verifier.MaxRequestBytes); err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
	}
	if *requestID != "" {
		bundle, fetchErr := lookup.Fetch(context.Background(), lookup.Config{BaseURL: *apiBase, APIKey: os.Getenv(*keyEnv)}, *requestID)
		if fetchErr != nil {
			fmt.Fprintln(errOut, fetchErr)
			return 2
		}
		if len(bundle.Attempts) > 1 && *attemptID == "" {
			fmt.Fprintln(errOut, "This request has several receipts. Select one with --attempt-id:")
			for _, a := range bundle.Attempts {
				fmt.Fprintln(errOut, a.ID)
			}
			return 2
		}
		var selected *lookup.Attempt
		for i := range bundle.Attempts {
			if *attemptID == "" || bundle.Attempts[i].ID == *attemptID {
				selected = &bundle.Attempts[i]
				break
			}
		}
		if selected == nil {
			fmt.Fprintln(errOut, "The selected attempt does not belong to this request.")
			return 2
		}
		if in, err = selected.Apply(in); err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
	}
	r := verifier.Verify(in)
	if *requestID != "" {
		r.Notes = append(r.Notes, "Request-ID to execution-ID mapping was supplied by the buyer API over TLS; the buyer request ID is not itself a field signed by the TEE.")
	}
	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
	} else {
		fmt.Fprintln(out, "TokHive verification:", r.Status)
		for _, c := range r.Checks {
			fmt.Fprintf(out, "[%s] %s: %s\n", c.Status, c.Label, c.Message)
		}
		if r.Receipt != nil {
			fmt.Fprintf(out, "\nExecution: %s\nUpstream: %s%s\nCompletion: %s (HTTP %d)\n", r.Receipt.JobID, r.Receipt.Host, r.Receipt.Path, r.Receipt.Completion, r.Receipt.StatusCode)
		}
		fmt.Fprintf(out, "\nReceipt verified: %t\nRequest verified: %t\nResponse verified: %t\n", r.Verified, r.RequestVerified, r.ResponseVerified)
		if r.Claims != nil {
			fmt.Fprintf(out, "Bound declarations (not independently recounted):\n  requested model: %s\n  response model: %s\n  input tokens: %s\n  output tokens: %s\n", r.Claims.RequestedModel, r.Claims.ResponseModel, r.Claims.InputTokens, r.Claims.OutputTokens)
		}
		for _, note := range r.Notes {
			fmt.Fprintln(out, "Note:", note)
		}
	}
	if r.Verified {
		return 0
	}
	if r.Status == "incomplete" {
		return 3
	}
	return 1
}

func readFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: expected a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: exceeds %d byte limit", path, limit)
	}
	return b, nil
}

func runServe(args []string, out, errOut io.Writer) int {
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	f.SetOutput(errOut)
	listen := f.String("listen", "127.0.0.1:8787", "loopback address for the static browser UI")
	apiBase := f.String("api-base-url", "https://api.tokhive.ai", "buyer verification API origin used by request-ID lookup")
	if err := f.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if f.NArg() != 0 {
		fmt.Fprintln(errOut, "serve accepts flags only")
		return 2
	}
	if _, err := lookup.ValidateBaseURL(*apiBase); err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || (host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback())) {
		fmt.Fprintln(errOut, "The preview server requires a loopback address, such as 127.0.0.1:8787.")
		return 2
	}
	assets, _ := fs.Sub(web.Assets, "static")
	if _, err := fs.Stat(assets, "verifier.wasm"); err != nil {
		fmt.Fprintln(errOut, "Browser engine is not built. Run make build, then use bin/tokhive-verify serve.")
		return 2
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	fmt.Fprintf(out, "TokHive Verifier: http://%s\nFiles stay in your browser. Ctrl+C to stop.\n", l.Addr())
	s := &http.Server{Handler: LookupHandler(assets, *apiBase), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	if err := s.Serve(l); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(errOut, err)
		return 2
	}
	return 0
}

// Handler serves static assets only. No upload endpoint or verification backend
// exists: the server never receives receipt or response file contents.
func Handler(assets fs.FS) http.Handler {
	files := http.FileServer(http.FS(assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; font-src 'self'; connect-src 'self'; worker-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Static files only", http.StatusMethodNotAllowed)
			return
		}
		files.ServeHTTP(w, r)
	})
}

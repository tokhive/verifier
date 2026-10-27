package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/tokhive/verifier"
	"github.com/tokhive/verifier/internal/testfixture"
	"github.com/tokhive/verifier/lookup"
)

func TestCLIRejectsSoftwareReceiptAndEmitsJSON(t *testing.T) {
	f, err := testfixture.New(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = f.WriteFiles(dir); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := Run([]string{"verify", "--json", "--expected-app", f.Epoch.ID.ApplicationID, "--response", filepath.Join(dir, "response.raw"), "--job-spec", filepath.Join(dir, "job-spec.cbor"), "--request", filepath.Join(dir, "request.raw"), filepath.Join(dir, "receipt.cbor")}, &out, &errOut)
	var report verifier.Report
	if code != 1 || json.Unmarshal(out.Bytes(), &report) != nil || report.Verified {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, &out, &errOut)
	}
}
func TestCLIUsageAndFileErrors(t *testing.T) {
	for _, args := range [][]string{{"verify"}, {"verify", "missing.cbor"}, {"serve", "--listen", "0.0.0.0:8787"}, {"verify", "--request-id", "req_test", "receipt.cbor"}} {
		var out, errOut bytes.Buffer
		if Run(args, &out, &errOut) != 2 {
			t.Fatalf("invalid args accepted: %v", args)
		}
	}
}
func TestLocalServerHeadersAndFileOnlyBehavior(t *testing.T) {
	assets := fstest.MapFS{"index.html": {Data: []byte("verifier")}}
	h := Handler(assets)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "wasm-unsafe-eval") {
		t.Fatal("headers")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/", nil))
	if w.Code != 405 {
		t.Fatal("file upload allowed")
	}
}
func TestLookupBridgeRejectsCrossOriginAndRebinding(t *testing.T) {
	h := LookupHandler(fstest.MapFS{}, "https://example.com")
	for _, test := range []struct{ host, origin, header string }{{"evil.example:8787", "", "1"}, {"127.0.0.1:8787", "https://evil.example", "1"}, {"127.0.0.1:8787", "", ""}} {
		r := httptest.NewRequest("POST", "http://127.0.0.1:8787/api/lookup", strings.NewReader(`{"request_id":"req_test","api_key":"secret"}`))
		r.Host = test.host
		r.Header.Set("Origin", test.origin)
		r.Header.Set("X-TokHive-Verifier", test.header)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("cross-origin lookup allowed: %d", w.Code)
		}
	}
}
func TestReadFileEnforcesSize(t *testing.T) {
	p := filepath.Join(t.TempDir(), "large")
	if err := os.WriteFile(p, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(p, 2); err == nil {
		t.Fatal("oversize file read")
	}
}

func buyerEvidenceServer(t *testing.T, multiple bool) (*httptest.Server, string) {
	t.Helper()
	f, err := testfixture.New(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(f.Bytes())
	bundle := lookup.Bundle{Version: 1, RequestID: "req_fixture", Attempts: []lookup.Attempt{{ID: hex.EncodeToString(f.Spec.JobID), ReceiptSHA256: hex.EncodeToString(h[:]), Receipt: f.Bytes()}}}
	if multiple {
		f.Spec.JobID = []byte("fedcba9876543210")
		f.Signed.Receipt.JobID = f.Spec.JobID
		f.Resign()
		hash := sha256.Sum256(f.Bytes())
		bundle.Attempts = append(bundle.Attempts, lookup.Attempt{ID: hex.EncodeToString(f.Spec.JobID), ReceiptSHA256: hex.EncodeToString(hash[:]), Receipt: f.Bytes()})
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/verification/requests/req_fixture" || r.Header.Get("Authorization") != "Bearer buyer-test-key" {
			t.Error("incorrect buyer transport")
		}
		json.NewEncoder(w).Encode(bundle)
	}))
	t.Cleanup(s.Close)
	return s, f.Epoch.ID.ApplicationID
}

func TestCLIRequestIDFetchesAndRunsRealVerification(t *testing.T) {
	s, app := buyerEvidenceServer(t, false)
	t.Setenv("TOKHIVE_TEST_KEY", "buyer-test-key")
	var out, errOut bytes.Buffer
	code := Run([]string{"verify", "--request-id", "req_fixture", "--api-base-url", s.URL, "--api-key-env", "TOKHIVE_TEST_KEY", "--expected-app", app, "--json"}, &out, &errOut)
	var report verifier.Report
	if code != 1 || json.Unmarshal(out.Bytes(), &report) != nil || report.Verified {
		t.Fatalf("lookup: exit=%d stdout=%s stderr=%s", code, &out, &errOut)
	}
	if strings.Contains(out.String(), "buyer-test-key") {
		t.Fatal("key leaked in report")
	}
}

func TestCLIRequestIDDoesNotSilentlyChooseAnAttempt(t *testing.T) {
	s, app := buyerEvidenceServer(t, true)
	t.Setenv("TOKHIVE_TEST_KEY", "buyer-test-key")
	var out, errOut bytes.Buffer
	code := Run([]string{"verify", "--request-id", "req_fixture", "--api-base-url", s.URL, "--api-key-env", "TOKHIVE_TEST_KEY", "--expected-app", app}, &out, &errOut)
	if code != 2 || !strings.Contains(errOut.String(), "--attempt-id") {
		t.Fatalf("ambiguous attempts: %d %s", code, &errOut)
	}
}

func TestLocalBuyerBridgeDownloadsEvidenceWithoutAnAdminSession(t *testing.T) {
	s, _ := buyerEvidenceServer(t, false)
	h := LookupHandler(fstest.MapFS{}, s.URL)
	r := httptest.NewRequest("POST", "http://127.0.0.1:8787/api/lookup", strings.NewReader(`{"request_id":"req_fixture","api_key":"buyer-test-key"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-TokHive-Verifier", "1")
	r.Header.Set("Origin", "http://127.0.0.1:8787")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "buyer-test-key") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("bridge: %d %s", w.Code, w.Body)
	}
}

package lookup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tokhive/verifier/internal/testfixture"
)

func testBundle(t *testing.T) Bundle {
	t.Helper()
	f, err := testfixture.New(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw := f.Bytes()
	h := sha256.Sum256(raw)
	return Bundle{Version: 1, RequestID: "req_fixture", Attempts: []Attempt{{ID: hex.EncodeToString(f.Spec.JobID), ReceiptSHA256: hex.EncodeToString(h[:]), Receipt: raw}}}
}
func TestBuyerLookupContract(t *testing.T) {
	b := testBundle(t)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/verification/requests/req_fixture" || r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("wrong buyer lookup")
		}
		json.NewEncoder(w).Encode(b)
	}))
	defer s.Close()
	got, err := Fetch(context.Background(), Config{BaseURL: s.URL, APIKey: "test-key"}, b.RequestID)
	if err != nil || len(got.Attempts) != 1 {
		t.Fatalf("lookup: %v", err)
	}
}
func TestLookupRejectsWrongIdentityAndTampering(t *testing.T) {
	for _, kind := range []string{"request", "digest", "attempt", "duplicate", "signature"} {
		t.Run(kind, func(t *testing.T) {
			b := testBundle(t)
			switch kind {
			case "request":
				b.RequestID = "other"
			case "digest":
				b.Attempts[0].ReceiptSHA256 = strings.Repeat("00", 32)
			case "attempt":
				b.Attempts[0].ID = strings.Repeat("ab", 16)
			case "duplicate":
				b.Attempts = append(b.Attempts, b.Attempts[0])
			case "signature":
				b.Attempts[0].Receipt[20] ^= 1
				h := sha256.Sum256(b.Attempts[0].Receipt)
				b.Attempts[0].ReceiptSHA256 = hex.EncodeToString(h[:])
			}
			if b.Validate("req_fixture") == nil {
				t.Fatal("bad bundle accepted")
			}
		})
	}
}
func TestLookupNeverFollowsRedirects(t *testing.T) {
	var leaked bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer target.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer s.Close()
	_, err := Fetch(context.Background(), Config{BaseURL: s.URL, APIKey: "test-key"}, "req_fixture")
	if err == nil || leaked {
		t.Fatal("redirect followed")
	}
}
func TestLookupRequiresSafeOriginAndBuyerCredential(t *testing.T) {
	for _, base := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/path", "https://example.com?key=secret", "file:///etc/passwd"} {
		if _, err := ValidateBaseURL(base); err == nil {
			t.Fatal("unsafe origin", base)
		}
	}
	if _, err := Fetch(context.Background(), Config{BaseURL: "https://example.com"}, "req_fixture"); err == nil {
		t.Fatal("missing key accepted")
	}
}
func TestLookupAuthenticationErrors(t *testing.T) {
	for _, status := range []int{401, 403, 404, 429, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer s.Close()
			_, err := Fetch(context.Background(), Config{BaseURL: s.URL, APIKey: "test-key"}, "req_fixture")
			if err == nil || strings.Contains(err.Error(), "test-key") {
				t.Fatal("unsafe error")
			}
		})
	}
}

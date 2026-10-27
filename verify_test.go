package verifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tokhive/tee/platform"
	"github.com/tokhive/tee/proof"
	"github.com/tokhive/verifier/internal/testfixture"
)

var testNow = time.Unix(1793000000, 0)

func fixture(t *testing.T) *testfixture.Fixture {
	t.Helper()
	f, err := testfixture.New(testNow)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func input(f *testfixture.Fixture) Input {
	return Input{Receipt: f.Bytes(), Options: Options{ExpectedApp: f.Epoch.ID.ApplicationID}}
}

// This seam isolates orchestration tests from hardware. Public Verify tests
// below exercise the actual cryptographic attestation verifier and reject fakes.
func acceptedHardware(platform.Identity, string) error { return nil }
func check(t *testing.T, r Report, id, status string) {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			if c.Status != status {
				t.Fatalf("%s = %s: %s", id, c.Status, c.Message)
			}
			return
		}
	}
	t.Fatalf("missing check %s", id)
}

func TestRealVerifierRejectsSoftwareEvidence(t *testing.T) {
	f := fixture(t)
	r := Verify(input(f))
	if r.Verified || r.Status != "failed" || r.Claims != nil {
		t.Fatalf("software evidence trusted: %+v", r)
	}
	check(t, r, "signature", "passed")
	check(t, r, "hardware", "failed")
}
func TestVerifiedReceiptIsNotAutomaticallyVerifiedContent(t *testing.T) {
	f := fixture(t)
	r := verify(input(f), testNow, acceptedHardware)
	if !r.Verified || r.RequestVerified || r.ResponseVerified {
		t.Fatalf("scope: %+v", r)
	}
	check(t, r, "response", "skipped")
}
func TestFullContentBindingAndDeclaredUsage(t *testing.T) {
	f := fixture(t)
	in := input(f)
	in.JobSpec = f.SpecBytes()
	in.Request = f.Request
	in.RequestProvided = true
	in.Response = f.Response
	in.ResponseProvided = true
	r := verify(in, testNow, acceptedHardware)
	if !r.Verified || !r.RequestVerified || !r.ResponseVerified || r.Claims == nil || r.Claims.RequestedModel != "fixture-model" || r.Claims.InputTokens != "5" || r.Claims.OutputTokens != "3" {
		t.Fatalf("content: %+v", r)
	}
	// The identical bytes still must not be called trusted if hardware fails.
	r = verify(in, testNow, func(platform.Identity, string) error { return errors.New("untrusted hardware") })
	if r.Verified || r.Claims != nil || r.RequestVerified || r.ResponseVerified {
		t.Fatal("content claims survived failed trust")
	}
}
func TestContentTampering(t *testing.T) {
	for _, kind := range []string{"receipt", "response", "request", "spec"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture(t)
			in := input(f)
			in.JobSpec = f.SpecBytes()
			in.Request = append([]byte(nil), f.Request...)
			in.RequestProvided = true
			in.Response = append([]byte(nil), f.Response...)
			in.ResponseProvided = true
			switch kind {
			case "receipt":
				f.Signed.Receipt.Host = "evil.example"
				in.Receipt = f.Bytes()
			case "response":
				in.Response[0] ^= 1
			case "request":
				in.Request[0] ^= 1
			case "spec":
				f.Spec.Host = "evil.example"
				in.JobSpec = f.SpecBytes()
			}
			r := verify(in, testNow, acceptedHardware)
			if r.Verified || r.Status != "failed" {
				t.Fatalf("tampering accepted: %+v", r)
			}
		})
	}
}
func TestMissingTrustOrEvidence(t *testing.T) {
	for _, kind := range []string{"application", "hardware", "spec"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture(t)
			in := input(f)
			switch kind {
			case "application":
				in.Options.ExpectedApp = ""
			case "hardware":
				f.Signed.Receipt.Attestation.Evidence = nil
				f.ResignBody()
				in.Receipt = f.Bytes()
			case "spec":
				in.Request = f.Request
				in.RequestProvided = true
			}
			r := verify(in, testNow, acceptedHardware)
			if r.Verified || r.Status != "incomplete" {
				t.Fatalf("missing %s accepted: %+v", kind, r)
			}
		})
	}
}
func TestHashOnlyExternalEvidence(t *testing.T) {
	f := fixture(t)
	f.Signed.Receipt.Attestation.Evidence = nil
	// Changing the inline representation requires signing that exact body.
	encoded, _ := f.Signed.Receipt.EncodeCanonical()
	sig, err := f.Epoch.Sign(proof.ReceiptSigningDomain, encoded)
	if err != nil {
		t.Fatal(err)
	}
	f.Signed.Signature = sig
	in := input(f)
	in.Evidence = f.Epoch.ID.Evidence
	r := verify(in, testNow, acceptedHardware)
	if !r.Verified {
		t.Fatalf("external evidence: %+v", r)
	}
	in.Evidence = []byte("other evidence")
	r = verify(in, testNow, acceptedHardware)
	check(t, r, "hardware", "failed")
}
func TestExpectationMismatches(t *testing.T) {
	for _, kind := range []string{"application", "policy", "host", "job", "platform", "age", "future"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture(t)
			in := input(f)
			switch kind {
			case "application":
				in.Options.ExpectedApp = "snp-app:" + strings.Repeat("ab", 32)
			case "policy":
				in.Options.ExpectedPolicy = strings.Repeat("ab", 32)
			case "host":
				in.Options.ExpectedHost = "wrong.example"
			case "job":
				in.Options.ExpectedJobID = strings.Repeat("ab", 16)
			case "platform":
				f.Epoch.ID.Platform = "simulated"
				f.Resign()
				in.Receipt = f.Bytes()
			case "age":
				in.Options.MaxAgeSeconds = 1
				f.Signed.Receipt.StartedAt -= 5
				f.Signed.Receipt.FinishedAt -= 5
				f.Resign()
				in.Receipt = f.Bytes()
			case "future":
				f.Signed.Receipt.FinishedAt += 301
				f.Resign()
				in.Receipt = f.Bytes()
			}
			r := verify(in, testNow, acceptedHardware)
			if r.Verified || r.Status != "failed" {
				t.Fatalf("mismatch accepted: %+v", r)
			}
		})
	}
}
func TestMalformedAndNonCanonicalInput(t *testing.T) {
	f := fixture(t)
	for _, raw := range [][]byte{nil, []byte("not cbor"), append(f.Bytes(), 0), bytes.Repeat([]byte{0}, MaxReceiptBytes+1)} {
		in := input(f)
		in.Receipt = raw
		r := Verify(in)
		if r.Status != "failed" || r.Verified {
			t.Fatal("malformed receipt trusted")
		}
	}
	in := input(f)
	in.Options.ExpectedApp = "snp-app:short"
	r := Verify(in)
	check(t, r, "configuration", "failed")
}
func TestEmptyResponseIsDifferentFromNoResponse(t *testing.T) {
	f := fixture(t)
	hash := proof.HashResponseStream(f.Spec.JobID, nil)
	f.Signed.Receipt.StreamHash = hash[:]
	f.Signed.Receipt.ResponseBytes = 0
	f.Resign()
	in := input(f)
	in.ResponseProvided = true
	r := verify(in, testNow, acceptedHardware)
	if !r.ResponseVerified {
		t.Fatalf("empty response: %+v", r)
	}
}
func TestAuthenticFailedExecutionIsNotClaimedSuccessful(t *testing.T) {
	f := fixture(t)
	f.Signed.Receipt.StatusCode = 500
	f.Signed.Receipt.Completion = proof.CompletionFailed
	f.Resign()
	r := verify(input(f), testNow, acceptedHardware)
	if !r.Verified || r.Receipt.Completion != "failed" || !strings.Contains(strings.Join(r.Notes, " "), "not describe a complete successful") {
		t.Fatalf("completion semantics: %+v", r)
	}
}
func TestClaimParsingJSONAndSSE(t *testing.T) {
	var claims Claims
	readResponseClaims(&claims, []byte("event: message_start\r\ndata: {\"message\":{\"model\":\"claude-fixture\",\"usage\":{\"input_tokens\":11}}}\r\n\r\nevent: message_delta\r\ndata: {\"usage\":{\"output_tokens\":7}}\r\n\r\ndata: [DONE]\r\n\r\n"))
	if claims.InputTokens != "11" || claims.OutputTokens != "7" || claims.ResponseModel != "claude-fixture" {
		t.Fatalf("SSE: %+v", claims)
	}
	readResponseClaims(&claims, []byte(`{"response":{"usage":{"input_tokens":9007199254740993,"output_tokens":0}}}`))
	if claims.InputTokens != "9007199254740993" || claims.OutputTokens != "0" {
		t.Fatalf("precision: %+v", claims)
	}
}
func TestReceiptSHA256(t *testing.T) {
	f := fixture(t)
	in := input(f)
	r := verify(in, testNow, acceptedHardware)
	h := sha256.Sum256(in.Receipt)
	if r.ReceiptSHA256 != hex.EncodeToString(h[:]) {
		t.Fatal("receipt digest")
	}
}

func FuzzVerifyRejectsMalformedInputWithoutPanic(f *testing.F) {
	f.Add([]byte("bad"))
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 8192 {
			t.Skip()
		}
		r := Verify(Input{Receipt: b})
		if r.Verified {
			t.Fatal("unconfigured random receipt trusted")
		}
	})
}

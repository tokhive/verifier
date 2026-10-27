// Package verifier checks TokHive execution receipts using the same cryptographic
// implementation in the native CLI and browser WebAssembly UI. It performs no I/O.
package verifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/tokhive/tee/platform"
	"github.com/tokhive/tee/platform/sevsnp"
	"github.com/tokhive/tee/proof"
)

const (
	MaxReceiptBytes  = 2 << 20
	MaxEvidenceBytes = 4 << 20
	MaxResponseBytes = 64 << 20
	MaxJobSpecBytes  = 2 << 20
	MaxRequestBytes  = 16 << 20
)

// Input contains original canonical-CBOR receipt bytes and optional evidence and
// raw response bytes. ResponseProvided distinguishes an empty file from no file.
type Input struct {
	Receipt          []byte
	Evidence         []byte
	Response         []byte
	ResponseProvided bool
	JobSpec          []byte
	Request          []byte
	RequestProvided  bool
	Options          Options
}

// Options are the user's expectations, never values automatically trusted from
// the receipt. ExpectedApp must be obtained from an independently trusted release.
type Options struct {
	ExpectedApp    string `json:"expected_app"`
	ExpectedPolicy string `json:"expected_policy,omitempty"`
	ExpectedHost   string `json:"expected_host,omitempty"`
	ExpectedJobID  string `json:"expected_job_id,omitempty"`
	MaxAgeSeconds  int64  `json:"max_age_seconds,omitempty"`
}

type Check struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Status   string `json:"status"` // passed, failed, skipped
	Required bool   `json:"required"`
	Message  string `json:"message"`
}

type ReceiptSummary struct {
	JobID               string `json:"job_id"`
	Platform            string `json:"platform"`
	Application         string `json:"application"`
	Host                string `json:"host"`
	Path                string `json:"path"`
	StatusCode          uint32 `json:"status_code"`
	Completion          string `json:"completion"`
	StartedAt           string `json:"started_at"`
	FinishedAt          string `json:"finished_at"`
	ResponseBytes       uint64 `json:"response_bytes"`
	StreamHash          string `json:"stream_hash"`
	PolicyHash          string `json:"policy_hash"`
	SigningKey          string `json:"signing_key"`
	EvidenceHash        string `json:"evidence_hash"`
	JobSpecHash         string `json:"job_spec_hash"`
	Method              string `json:"method"`
	Provider            string `json:"provider"`
	RequestBytes        uint64 `json:"request_bytes"`
	ChunkCount          uint64 `json:"chunk_count"`
	ProviderSeq         uint64 `json:"provider_seq"`
	ResponseHeadersHash string `json:"response_headers_hash,omitempty"`
}

// Report distinguishes a verified receipt from a verified response. An absent
// response is never reported as a successful response comparison.
type Report struct {
	Version          int             `json:"version"`
	Status           string          `json:"status"` // verified, incomplete, failed
	Verified         bool            `json:"verified"`
	ResponseVerified bool            `json:"response_verified"`
	RequestVerified  bool            `json:"request_verified"`
	VerifiedAt       string          `json:"verified_at"`
	ReceiptSHA256    string          `json:"receipt_sha256"`
	Expectations     Options         `json:"expectations"`
	Checks           []Check         `json:"checks"`
	Receipt          *ReceiptSummary `json:"receipt,omitempty"`
	Notes            []string        `json:"notes"`
	Claims           *Claims         `json:"bound_claims,omitempty"`
}

func (r *Report) add(id, label, status string, required bool, message string) {
	r.Checks = append(r.Checks, Check{id, label, status, required, message})
}

func (r *Report) finish() Report {
	r.Status = "verified"
	for _, c := range r.Checks {
		if c.Required && c.Status == "skipped" {
			r.Status = "incomplete"
		}
	}
	for _, c := range r.Checks {
		if c.Status == "failed" {
			r.Status = "failed"
		}
	}
	r.Verified = r.Status == "verified"
	if r.Verified {
		for _, c := range r.Checks {
			if c.ID == "response" && c.Status == "passed" {
				r.ResponseVerified = true
			}
			if c.ID == "request" && c.Status == "passed" {
				r.RequestVerified = true
			}
		}
	}
	if !r.Verified {
		r.Claims = nil
	}
	return *r
}

// Verify performs offline verification against embedded AMD/AWS roots. Missing
// trust configuration yields an incomplete report, never a verified result.
// Certificates are checked at the current time; expired historical evidence is
// refused. This API does not provide a user-controlled verification clock.
func Verify(in Input) Report {
	return verify(in, time.Now(), func(id platform.Identity, app string) error {
		return (sevsnp.Verifier{ExpectedApp: app}).CheckEvidence(id)
	})
}

func verify(in Input, now time.Time, checkEvidence func(platform.Identity, string) error) Report {
	r := Report{Version: 1, VerifiedAt: now.UTC().Format(time.RFC3339), Expectations: in.Options,
		Checks: []Check{}, Notes: []string{
			"Model and usage can be indirectly bound through matching request/response bytes. They remain upstream declarations, not independent model identification or token recounting.",
			"Response comparison requires the exact upstream response body bytes; API transformations can change them.",
			"Hardware evidence is checked at the current time. Expired certificate chains are refused; this is not archival timestamp verification.",
		}}
	if len(in.Receipt) == 0 || len(in.Receipt) > MaxReceiptBytes || len(in.Evidence) > MaxEvidenceBytes || len(in.Response) > MaxResponseBytes || len(in.JobSpec) > MaxJobSpecBytes || len(in.Request) > MaxRequestBytes {
		r.add("input", "Input files", "failed", true, "Missing receipt or file size limit exceeded (receipt/spec 2 MiB, evidence 4 MiB, request 16 MiB, response 64 MiB).")
		return r.finish()
	}
	if err := validateOptions(in.Options); err != nil {
		r.add("configuration", "Verification expectations", "failed", true, err.Error())
		return r.finish()
	}
	sum := sha256.Sum256(in.Receipt)
	r.ReceiptSHA256 = hex.EncodeToString(sum[:])
	signed, err := proof.DecodeAndVerify(in.Receipt, proof.VerifyOptions{})
	if err != nil {
		r.add("signature", "Canonical receipt and signature", "failed", true, err.Error())
		return r.finish()
	}
	r.add("signature", "Canonical receipt and signature", "passed", true, "Canonical CBOR and signature match the receipt's declared public key. Hardware trust is checked separately.")
	p := signed.Receipt
	a := p.Attestation
	r.Receipt = &ReceiptSummary{
		JobID: hex.EncodeToString(p.JobID), Platform: a.Platform, Application: a.ApplicationID,
		Host: p.Host, Path: p.Path, StatusCode: p.StatusCode, Completion: p.Completion.String(),
		StartedAt: time.Unix(p.StartedAt, 0).UTC().Format(time.RFC3339), FinishedAt: time.Unix(p.FinishedAt, 0).UTC().Format(time.RFC3339),
		ResponseBytes: p.ResponseBytes, StreamHash: hex.EncodeToString(p.StreamHash), PolicyHash: hex.EncodeToString(p.PolicyHash),
		SigningKey: hex.EncodeToString(a.KeyID), EvidenceHash: hex.EncodeToString(a.EvidenceHash),
		JobSpecHash: hex.EncodeToString(p.JobSpecHash), Method: p.Method, Provider: p.Provider,
		RequestBytes: p.RequestBytes, ChunkCount: p.ChunkCount, ProviderSeq: p.ProviderSeq,
		ResponseHeadersHash: hex.EncodeToString(p.ResponseHeadersHash),
	}
	if p.FinishedAt > now.Unix()+300 {
		r.add("time", "Execution time", "failed", true, "Receipt finishes more than five minutes in the future.")
	} else if in.Options.MaxAgeSeconds > 0 && now.Unix()-p.FinishedAt > in.Options.MaxAgeSeconds {
		r.add("time", "Execution time", "failed", true, "Receipt is older than the configured maximum age.")
	} else {
		r.add("time", "Execution time", "passed", true, "Execution times satisfy the configured age and future-clock checks.")
	}
	if a.Platform != platform.PlatformAWSSEVSNP {
		r.add("hardware", "Hardware attestation", "failed", true, "Unsupported platform: "+a.Platform+". Only AWS SEV-SNP is accepted; simulated receipts are refused.")
	} else {
		id, _ := p.Identity() // DecodeAndVerify already validates this structure.
		if len(in.Evidence) > 0 {
			if len(id.Evidence) > 0 && !bytes.Equal(in.Evidence, id.Evidence) {
				r.add("hardware", "Hardware attestation", "failed", true, "External evidence conflicts with the receipt's inline evidence.")
				return r.finish()
			}
			id.Evidence = in.Evidence
		}
		if len(id.Evidence) == 0 {
			r.add("hardware", "Hardware attestation", "skipped", true, "This receipt contains only an evidence hash. Supply the matching evidence file.")
		} else if digest := sha256.Sum256(id.Evidence); digest != id.EvidenceHash {
			r.add("hardware", "Hardware attestation", "failed", true, "Evidence SHA-256 does not match the signed evidence hash.")
		} else if err := checkEvidence(id, in.Options.ExpectedApp); err != nil {
			r.add("hardware", "Hardware attestation", "failed", true, err.Error())
		} else {
			r.add("hardware", "Hardware attestation", "passed", true, "AMD/AWS trust chains, hardware policy and signing-key binding verified.")
		}
	}
	if in.Options.ExpectedApp == "" {
		r.add("application", "Expected application", "skipped", true, "Supply an independently trusted snp-app:<sha256> release identity. The receipt's own claim is not a trust anchor.")
	} else {
		match(&r, "application", "Expected application", in.Options.ExpectedApp, a.ApplicationID, true)
	}
	optionalMatch(&r, "policy", "Expected policy hash", in.Options.ExpectedPolicy, hex.EncodeToString(p.PolicyHash))
	optionalMatch(&r, "host", "Expected upstream host", in.Options.ExpectedHost, p.Host)
	optionalMatch(&r, "job", "Expected execution ID", in.Options.ExpectedJobID, hex.EncodeToString(p.JobID))
	checkRequest(&r, in, p)
	if !in.ResponseProvided {
		r.add("response", "Response body", "skipped", false, "No response file supplied. Response content has not been compared.")
	} else if digest := proof.HashResponseStream(p.JobID, [][]byte{in.Response}); !bytes.Equal(digest[:], p.StreamHash) || uint64(len(in.Response)) != p.ResponseBytes {
		r.add("response", "Response body", "failed", true, "Response hash or byte count does not match the signed receipt.")
	} else {
		r.add("response", "Response body", "passed", true, "Exact response bytes match the signed, execution-bound stream hash and byte count.")
		if r.Claims == nil {
			r.Claims = &Claims{}
		}
		readResponseClaims(r.Claims, in.Response)
	}
	if p.Completion != proof.CompletionComplete || p.StatusCode < 200 || p.StatusCode >= 300 {
		r.Notes = append(r.Notes, "Authentic execution can still have failed or been truncated. This receipt does not describe a complete successful 2xx response.")
	}
	return r.finish()
}

func validateOptions(o Options) error {
	if o.ExpectedApp != "" && (!strings.HasPrefix(o.ExpectedApp, "snp-app:") || !validHex(strings.TrimPrefix(o.ExpectedApp, "snp-app:"), 32)) {
		return fmt.Errorf("expected application must be snp-app: followed by 64 lowercase hex characters")
	}
	if o.ExpectedPolicy != "" && !validHex(o.ExpectedPolicy, 32) {
		return fmt.Errorf("expected policy must be 64 lowercase hex characters")
	}
	if o.ExpectedJobID != "" && !validHex(o.ExpectedJobID, 16) {
		return fmt.Errorf("expected execution ID must be 32 lowercase hex characters (the receipt job_id, not a buyer request ID)")
	}
	if o.MaxAgeSeconds < 0 {
		return fmt.Errorf("maximum age cannot be negative")
	}
	if len(o.ExpectedHost) > 253 || strings.ContainsAny(o.ExpectedHost, "/\\\r\n\t ") {
		return fmt.Errorf("expected host must be a hostname, without a scheme or path")
	}
	return nil
}

func validHex(s string, size int) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == size && s == strings.ToLower(s)
}

func optionalMatch(r *Report, id, label, expected, actual string) {
	if expected == "" {
		r.add(id, label, "skipped", false, "No independent expectation supplied.")
		return
	}
	match(r, id, label, expected, actual, true)
}

func match(r *Report, id, label, expected, actual string, required bool) {
	if expected != actual {
		r.add(id, label, "failed", required, fmt.Sprintf("Expected %q; receipt declares %q.", expected, actual))
		return
	}
	r.add(id, label, "passed", required, "Matches the supplied expectation; application trust also requires a passing hardware check.")
}

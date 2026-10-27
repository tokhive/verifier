// Package lookup retrieves buyer-owned evidence from the public verification
// endpoint. Transport and identity checks do not replace cryptographic verification.
package lookup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/tokhive/tee/proof"
	"github.com/tokhive/verifier"
)

const MaxBundleBytes = 24 << 20

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// Bundle is the public buyer evidence contract. Binary values are JSON base64.
// It deliberately contains neither credentials, plaintext content nor an
// authoritative "verified" flag. Each attempt must be checked independently.
type Bundle struct {
	Version   int       `json:"version"`
	RequestID string    `json:"request_id"`
	Attempts  []Attempt `json:"attempts"`
}

type Attempt struct {
	ID            string `json:"id"`
	ReceiptSHA256 string `json:"receipt_sha256"`
	Receipt       []byte `json:"receipt"`
	Evidence      []byte `json:"evidence,omitempty"`
	JobSpec       []byte `json:"job_spec,omitempty"`
}

type Config struct{ BaseURL, APIKey string }

func ValidateBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("API base URL must be an origin without credentials, path, query or fragment")
	}
	loopback := u.Hostname() == "localhost" || (net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback())
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return nil, fmt.Errorf("API base URL requires HTTPS (HTTP is allowed only on loopback for development)")
	}
	return u, nil
}

// Fetch uses a buyer API key, never an administrator session. Redirects are
// refused so a response cannot send the credential to another endpoint.
func Fetch(ctx context.Context, cfg Config, requestID string) (Bundle, error) {
	var result Bundle
	u, err := ValidateBaseURL(cfg.BaseURL)
	if err != nil {
		return result, err
	}
	if !identifier.MatchString(requestID) {
		return result, fmt.Errorf("invalid request ID")
	}
	if cfg.APIKey == "" || len(cfg.APIKey) > 512 || strings.ContainsAny(cfg.APIKey, "\r\n\t ") {
		return result, fmt.Errorf("provide a valid buyer API key")
	}
	u.Path = "/v1/verification/requests/" + requestID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return result, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return result, fmt.Errorf("evidence lookup connection failed: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		switch res.StatusCode {
		case 401:
			return result, fmt.Errorf("buyer API key was not accepted (HTTP 401)")
		case 403, 404:
			return result, fmt.Errorf("request evidence is unavailable, not owned by this buyer, or the buyer endpoint has not been deployed (HTTP %d)", res.StatusCode)
		case 409:
			return result, fmt.Errorf("this request has no execution receipts yet; try again after execution finishes (HTTP 409)")
		case 429:
			return result, fmt.Errorf("evidence lookup is rate limited; try again later (HTTP 429)")
		default:
			return result, fmt.Errorf("evidence lookup returned HTTP %d", res.StatusCode)
		}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, MaxBundleBytes+1))
	if err != nil {
		return result, err
	}
	if len(raw) > MaxBundleBytes {
		return result, fmt.Errorf("evidence bundle exceeds the 24 MiB limit")
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return result, fmt.Errorf("invalid evidence bundle JSON")
	}
	if err := result.Validate(requestID); err != nil {
		return Bundle{}, err
	}
	return result, nil
}

func (b Bundle) Validate(requestID string) error {
	if b.Version != 1 || b.RequestID != requestID {
		return fmt.Errorf("bundle version or request ID mismatch")
	}
	if len(b.Attempts) == 0 {
		return fmt.Errorf("this request has no execution receipts yet")
	}
	if len(b.Attempts) > 32 {
		return fmt.Errorf("bundle contains more than 32 execution attempts")
	}
	seen := map[string]bool{}
	for _, a := range b.Attempts {
		if !identifier.MatchString(a.ID) || seen[a.ID] {
			return fmt.Errorf("invalid or duplicate execution attempt ID")
		}
		seen[a.ID] = true
		if len(a.Receipt) == 0 || len(a.Receipt) > verifier.MaxReceiptBytes || len(a.Evidence) > verifier.MaxEvidenceBytes || len(a.JobSpec) > verifier.MaxJobSpecBytes {
			return fmt.Errorf("missing or oversized attempt evidence")
		}
		hash := sha256.Sum256(a.Receipt)
		if hex.EncodeToString(hash[:]) != a.ReceiptSHA256 {
			return fmt.Errorf("downloaded receipt SHA-256 does not match the evidence manifest")
		}
		signed, err := proof.DecodeAndVerify(a.Receipt, proof.VerifyOptions{})
		if err != nil {
			return fmt.Errorf("downloaded receipt signature is invalid: %w", err)
		}
		if hex.EncodeToString(signed.Receipt.JobID) != a.ID {
			return fmt.Errorf("downloaded receipt belongs to a different execution attempt")
		}
	}
	return nil
}

// Apply combines downloaded evidence with local files. Conflicts are refused;
// neither a local file nor the server may silently replace other evidence.
func (a Attempt) Apply(in verifier.Input) (verifier.Input, error) {
	if len(in.Receipt) > 0 && !bytes.Equal(in.Receipt, a.Receipt) {
		return in, fmt.Errorf("local receipt conflicts with downloaded receipt")
	}
	in.Receipt = a.Receipt
	if len(a.Evidence) > 0 {
		if len(in.Evidence) > 0 && !bytes.Equal(in.Evidence, a.Evidence) {
			return in, fmt.Errorf("local evidence conflicts with downloaded evidence")
		}
		in.Evidence = a.Evidence
	}
	if len(a.JobSpec) > 0 {
		if len(in.JobSpec) > 0 && !bytes.Equal(in.JobSpec, a.JobSpec) {
			return in, fmt.Errorf("local task specification conflicts with downloaded specification")
		}
		in.JobSpec = a.JobSpec
	}
	return in, nil
}

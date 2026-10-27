package verifier

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/tokhive/tee/jobs"
	"github.com/tokhive/tee/proof"
)

// Claims are declarations extracted only from hash-matching content and only
// included in a report when the receipt's full trust checks pass. Token counts
// are decimal strings to preserve precision across Go and JavaScript.
type Claims struct {
	RequestedModel string `json:"requested_model,omitempty"`
	ResponseModel  string `json:"response_model,omitempty"`
	InputTokens    string `json:"input_tokens,omitempty"`
	OutputTokens   string `json:"output_tokens,omitempty"`
}

func checkRequest(r *Report, in Input, p proof.Receipt) {
	if len(in.JobSpec) == 0 {
		r.add("job_spec", "Task specification", "skipped", in.RequestProvided, "Supply the canonical-CBOR task specification to link a request body to the receipt.")
		if in.RequestProvided {
			r.add("request", "Request body", "skipped", true, "A request body alone cannot be linked to the receipt without its task specification.")
		}
		return
	}
	var spec jobs.Spec
	dm, _ := (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, MaxNestedLevels: 16, MaxArrayElements: 1024, MaxMapPairs: 1024}).DecMode()
	err := dm.Unmarshal(in.JobSpec, &spec)
	if err == nil {
		err = spec.Validate()
	}
	encoded, encErr := spec.EncodeCanonical()
	if err == nil && encErr != nil {
		err = encErr
	}
	if err == nil && !bytes.Equal(encoded, in.JobSpec) {
		err = fmt.Errorf("task specification is not canonical CBOR")
	}
	hash, hashErr := spec.Hash()
	if err == nil && hashErr != nil {
		err = hashErr
	}
	if err == nil && (!bytes.Equal(hash[:], p.JobSpecHash) || !bytes.Equal(spec.JobID, p.JobID) || spec.Provider != p.Provider || spec.Method != p.Method || spec.Host != p.Host || spec.Path != p.Path) {
		err = fmt.Errorf("task specification does not match the signed hash or execution fields")
	}
	if err != nil {
		r.add("job_spec", "Task specification", "failed", true, err.Error())
		return
	}
	r.add("job_spec", "Task specification", "passed", true, "Canonical task specification matches the signed execution and specification hash.")
	if !in.RequestProvided {
		r.add("request", "Request body", "skipped", false, "No raw request body supplied.")
		return
	}
	if !spec.MatchesBody(in.Request) || uint64(len(in.Request)) != p.RequestBytes {
		r.add("request", "Request body", "failed", true, "Request body hash or byte count does not match the task specification and receipt.")
		return
	}
	r.add("request", "Request body", "passed", true, "Exact request bytes match the task body hash, which is bound through the signed specification hash.")
	if r.Claims == nil {
		r.Claims = &Claims{}
	}
	var body struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(in.Request, &body) == nil && len(body.Model) <= 256 {
		r.Claims.RequestedModel = body.Model
	}
}

func readResponseClaims(dst *Claims, raw []byte) {
	if readClaimObject(dst, raw) {
		return
	}
	// Parse SSE data payloads without altering the bytes used for verification.
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 4<<20)
	var data []string
	flush := func() {
		if len(data) > 0 {
			readClaimObject(dst, []byte(strings.Join(data, "\n")))
			data = nil
		}
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	flush()
}

func readClaimObject(dst *Claims, raw []byte) bool {
	return readClaimObjectAtDepth(dst, raw, 0)
}

func readClaimObjectAtDepth(dst *Claims, raw []byte, depth int) bool {
	if depth > 4 || len(raw) > 4<<20 {
		return false
	}
	var body struct {
		Model    string                     `json:"model"`
		Usage    map[string]json.RawMessage `json:"usage"`
		Response json.RawMessage            `json:"response"`
		Message  json.RawMessage            `json:"message"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return false
	}
	if body.Model != "" && len(body.Model) <= 256 {
		dst.ResponseModel = body.Model
	}
	readCount := func(keys ...string) string {
		for _, k := range keys {
			if b := body.Usage[k]; len(b) > 0 {
				if n, err := strconv.ParseUint(string(b), 10, 64); err == nil {
					return strconv.FormatUint(n, 10)
				}
			}
		}
		return ""
	}
	if n := readCount("input_tokens", "prompt_tokens"); n != "" {
		dst.InputTokens = n
	}
	if n := readCount("output_tokens", "completion_tokens"); n != "" {
		dst.OutputTokens = n
	}
	// Common Responses and Anthropic SSE envelopes.
	if len(body.Response) > 0 {
		readClaimObjectAtDepth(dst, body.Response, depth+1)
	}
	if len(body.Message) > 0 {
		readClaimObjectAtDepth(dst, body.Message, depth+1)
	}
	return true
}

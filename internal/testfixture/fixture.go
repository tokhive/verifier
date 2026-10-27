// Package testfixture creates software-signed fixtures. They are deliberately
// NOT genuine hardware evidence and the public verifier must always refuse them.
package testfixture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"

	"github.com/tokhive/tee/jobs"
	"github.com/tokhive/tee/platform"
	"github.com/tokhive/tee/proof"
)

type Epoch struct {
	Key *ecdsa.PrivateKey
	ID  platform.Identity
}

func (e Epoch) Identity() platform.Identity { return platform.CloneIdentity(e.ID) }
func (e Epoch) Sign(domain string, payload []byte) (platform.Signature, error) {
	digest, err := platform.SigningDigest(domain, payload)
	if err != nil {
		return platform.Signature{}, err
	}
	sig, err := ecdsa.SignASN1(rand.Reader, e.Key, digest[:])
	return platform.Signature{Algorithm: platform.SignatureAlgorithmECDSAP256SHA256ASN1, KeyID: e.ID.KeyID, Value: sig}, err
}

type Fixture struct {
	Epoch             Epoch
	Signed            proof.SignedReceipt
	Spec              jobs.Spec
	Request, Response []byte
}

func New(now time.Time) (*Fixture, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	app := sha256.Sum256([]byte("test-only application"))
	evidence := []byte("TEST ONLY: not AMD/AWS attestation")
	f := &Fixture{Epoch: Epoch{key, platform.Identity{Platform: platform.PlatformAWSSEVSNP, AttestationType: "sev-snp", ApplicationID: "snp-app:" + hex.EncodeToString(app[:]), PublicKeyDER: pub, KeyID: sha256.Sum256(pub), Evidence: evidence, EvidenceHash: sha256.Sum256(evidence)}}, Request: []byte(`{"model":"fixture-model","input":"hello"}`), Response: []byte(`{"model":"fixture-model","usage":{"input_tokens":5,"output_tokens":3}}`)}
	bodyHash := jobs.HashBody(f.Request)
	f.Spec = jobs.Spec{Version: 1, JobID: []byte("0123456789abcdef"), Provider: "fixture-provider", Method: "POST", Host: "api.openai.com", Path: "/v1/responses", Headers: map[string]string{"content-type": "application/json"}, BodyHash: bodyHash[:], Nonce: make([]byte, 16), ExpiresAt: now.Add(time.Minute).Unix(), MaxResponseBytes: 1 << 20, Stream: true}
	specHash, err := f.Spec.Hash()
	if err != nil {
		return nil, err
	}
	stream := proof.HashResponseStream(f.Spec.JobID, [][]byte{f.Response})
	policy := sha256.Sum256([]byte("fixture policy"))
	r := proof.Receipt{Version: 1, JobID: f.Spec.JobID, JobSpecHash: specHash[:], Provider: f.Spec.Provider, Method: f.Spec.Method, Host: f.Spec.Host, Path: f.Spec.Path, StatusCode: 200, StreamHash: stream[:], ChunkCount: 1, ResponseBytes: uint64(len(f.Response)), Completion: proof.CompletionComplete, StartedAt: now.Add(-time.Second).Unix(), FinishedAt: now.Unix(), PolicyHash: policy[:], RequestBytes: uint64(len(f.Request)), ProviderSeq: 1}
	signer := proof.NewSigner(f.Epoch)
	signer.IncludeEvidence = true
	f.Signed, err = signer.Sign(r)
	return f, err
}
func (f *Fixture) Bytes() []byte {
	b, err := f.Signed.EncodeCanonical()
	if err != nil {
		panic(err)
	}
	return b
}
func (f *Fixture) SpecBytes() []byte {
	b, err := f.Spec.EncodeCanonical()
	if err != nil {
		panic(err)
	}
	return b
}
func (f *Fixture) Resign() {
	signer := proof.NewSigner(f.Epoch)
	signer.IncludeEvidence = true
	signed, err := signer.Sign(f.Signed.Receipt)
	if err != nil {
		panic(err)
	}
	f.Signed = signed
}
func (f *Fixture) ResignBody() {
	b, err := f.Signed.Receipt.EncodeCanonical()
	if err != nil {
		panic(err)
	}
	sig, err := f.Epoch.Sign(proof.ReceiptSigningDomain, b)
	if err != nil {
		panic(err)
	}
	f.Signed.Signature = sig
}

// WriteFiles writes an explicit rejection demo for CLI/browser integration QA.
func (f *Fixture) WriteFiles(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	for name, b := range map[string][]byte{"receipt.cbor": f.Bytes(), "job-spec.cbor": f.SpecBytes(), "request.raw": f.Request, "response.raw": f.Response, "evidence.bin": f.Epoch.ID.Evidence, "expected-app.txt": []byte(f.Epoch.ID.ApplicationID)} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			return err
		}
	}
	return nil
}

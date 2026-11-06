package verifier

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

// ReleaseCatalog is the small public view consumed by the standalone
// verifier. The catalog is distributed separately from the WASM engine so a
// Secure Boot key rotation does not require changing the verification code.
type ReleaseCatalog struct {
	Version  int              `json:"version"`
	Releases []CatalogRelease `json:"releases"`
}

type CatalogRelease struct {
	ApplicationID                    string `json:"application_id"`
	SecureBootReleasePublicKeyPEM    string `json:"secure_boot_release_public_key_pem,omitempty"`
	SecureBootReleasePublicKeySHA256 string `json:"secure_boot_release_public_key_sha256,omitempty"`
}

// LoadReleaseCatalog parses a catalog obtained from the independently trusted
// release source. It does not trust any application identity from a receipt.
func LoadReleaseCatalog(raw []byte) (ReleaseCatalog, error) {
	var catalog ReleaseCatalog
	if err := json.Unmarshal(raw, &catalog); err != nil {
		return ReleaseCatalog{}, fmt.Errorf("decode release catalog: %w", err)
	}
	if catalog.Version != 1 {
		return ReleaseCatalog{}, fmt.Errorf("unsupported release catalog version %d", catalog.Version)
	}
	return catalog, nil
}

// ReleasePublicKeyFor returns the catalog key for an independently supplied
// application identity. Missing mappings are errors so Secure Boot evidence
// cannot silently fall back to a compiled key.
func (c ReleaseCatalog) ReleasePublicKeyFor(applicationID string) ([]byte, error) {
	for _, release := range c.Releases {
		if release.ApplicationID != applicationID {
			continue
		}
		if release.SecureBootReleasePublicKeyPEM == "" {
			return nil, fmt.Errorf("release %q has no Secure Boot release public key", applicationID)
		}
		if release.SecureBootReleasePublicKeySHA256 != "" {
			block, _ := pem.Decode([]byte(release.SecureBootReleasePublicKeyPEM))
			if block == nil || block.Type != "PUBLIC KEY" {
				return nil, fmt.Errorf("release %q has an invalid Secure Boot public key PEM", applicationID)
			}
			if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
				return nil, fmt.Errorf("release %q has an invalid Secure Boot public key: %w", applicationID, err)
			}
			digest := sha256.Sum256(block.Bytes)
			if hex.EncodeToString(digest[:]) != release.SecureBootReleasePublicKeySHA256 {
				return nil, fmt.Errorf("release %q Secure Boot public key fingerprint does not match the catalog", applicationID)
			}
		}
		return []byte(release.SecureBootReleasePublicKeyPEM), nil
	}
	return nil, fmt.Errorf("release catalog has no application %q", applicationID)
}

// LoadReleaseCatalogFile is used by the native CLI. The browser fetches the
// same catalog as a static runtime asset instead of asking the user to choose
// a key file.
func LoadReleaseCatalogFile(path string) (ReleaseCatalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ReleaseCatalog{}, err
	}
	return LoadReleaseCatalog(raw)
}

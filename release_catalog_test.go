package verifier

import (
	"strings"
	"testing"
)

func TestReleaseCatalogResolvesPublicKeyByApplication(t *testing.T) {
	catalog, err := LoadReleaseCatalog([]byte(`{"version":1,"releases":[{"application_id":"snp-app:abc","secure_boot_release_public_key_pem":"-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	key, err := catalog.ReleasePublicKeyFor("snp-app:abc")
	if err != nil || !strings.Contains(string(key), "BEGIN PUBLIC KEY") {
		t.Fatalf("resolved key = %q, err = %v", key, err)
	}
	if _, err := catalog.ReleasePublicKeyFor("snp-app:missing"); err == nil {
		t.Fatal("missing application resolved a key")
	}
}

func TestReleaseCatalogRejectsUnknownVersion(t *testing.T) {
	if _, err := LoadReleaseCatalog([]byte(`{"version":2,"releases":[]}`)); err == nil {
		t.Fatal("accepted unknown catalog version")
	}
}

func TestReleaseCatalogRejectsFingerprintMismatch(t *testing.T) {
	catalog, err := LoadReleaseCatalog([]byte(`{"version":1,"releases":[{"application_id":"snp-app:abc","secure_boot_release_public_key_pem":"-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n","secure_boot_release_public_key_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.ReleasePublicKeyFor("snp-app:abc"); err == nil {
		t.Fatal("accepted a mismatched public key fingerprint")
	}
}

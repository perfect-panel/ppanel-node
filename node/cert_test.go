package node

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateSelfSslCertificateFingerprint(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.cer")
	keyPath := filepath.Join(dir, "test.key")

	if err := generateSelfSslCertificate("tls.example.com", certPath, keyPath); err != nil {
		t.Fatalf("generateSelfSslCertificate() error = %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key file not created: %v", err)
	}

	fingerprint, err := certFingerprintSHA256(certPath)
	if err != nil {
		t.Fatalf("certFingerprintSHA256() error = %v", err)
	}
	if len(fingerprint) != 64 {
		t.Fatalf("fingerprint length = %d, want 64", len(fingerprint))
	}

	matched, err := selfCertificateMatchesDomain(certPath, "tls.example.com")
	if err != nil {
		t.Fatalf("selfCertificateMatchesDomain() error = %v", err)
	}
	if !matched {
		t.Fatal("selfCertificateMatchesDomain() = false, want true")
	}

	matched, err = selfCertificateMatchesDomain(certPath, "other.example.com")
	if err != nil {
		t.Fatalf("selfCertificateMatchesDomain(other) error = %v", err)
	}
	if matched {
		t.Fatal("selfCertificateMatchesDomain(other) = true, want false")
	}
}

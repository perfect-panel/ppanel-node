package node

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	vCore "github.com/perfect-panel/ppanel-node/core"
)

func TestGenerateSelfSSLCertificateCreatesUsableSecurePair(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.cer")
	keyPath := filepath.Join(dir, "node.key")
	if err := generateSelfSslCertificate("node.example.test", certPath, keyPath); err != nil {
		t.Fatalf("generateSelfSslCertificate() error = %v", err)
	}

	cert, err := loadUsableCertificate(certPath, keyPath, "node.example.test")
	if err != nil {
		t.Fatalf("loadUsableCertificate() error = %v", err)
	}
	if cert.Subject.CommonName != "node.example.test" {
		t.Fatalf("CommonName = %q, want node.example.test", cert.Subject.CommonName)
	}
	if _, err := loadUsableCertificate(certPath, keyPath, "other.example.test"); err == nil {
		t.Fatal("loadUsableCertificate() accepted a certificate for another hostname")
	}

	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if got := keyInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("private key permissions = %o, want 600", got)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		t.Fatalf("private key PEM type = %v, want EC PRIVATE KEY", block)
	}
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse ECDSA private key: %v", err)
	}
	if privateKey.Curve.Params().Name != elliptic.P256().Params().Name {
		t.Fatalf("private key curve = %v, want P-256", privateKey.Curve.Params().Name)
	}
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatalf("certificate public key algorithm = %v, want ECDSA", cert.PublicKeyAlgorithm)
	}
	if !certificateUsesECDSAP256(cert) {
		t.Fatal("certificateUsesECDSAP256() = false, want true")
	}
	if certificateUsesECDSAP256(&x509.Certificate{}) {
		t.Fatal("certificateUsesECDSAP256() accepted a certificate without an ECDSA P-256 key")
	}
	sum := sha256.Sum256(cert.Raw)
	if got, want := certificateSHA256(cert), hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("certificateSHA256() = %q, want %q", got, want)
	}
	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("stat certificate: %v", err)
	}
	if got := certInfo.Mode().Perm(); got != 0o644 {
		t.Fatalf("certificate permissions = %o, want 644", got)
	}
}

func TestLoadUsableCertificateRejectsMismatchedKey(t *testing.T) {
	dir := t.TempDir()
	firstCert := filepath.Join(dir, "first.cer")
	firstKey := filepath.Join(dir, "first.key")
	secondCert := filepath.Join(dir, "second.cer")
	secondKey := filepath.Join(dir, "second.key")
	if err := generateSelfSslCertificate("node.example.test", firstCert, firstKey); err != nil {
		t.Fatalf("generate first certificate: %v", err)
	}
	if err := generateSelfSslCertificate("node.example.test", secondCert, secondKey); err != nil {
		t.Fatalf("generate second certificate: %v", err)
	}
	if _, err := loadUsableCertificate(firstCert, secondKey, "node.example.test"); err == nil {
		t.Fatal("loadUsableCertificate() succeeded with a mismatched private key")
	}
}

func TestSecurePrivateKeyFileTightensExistingPermissions(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "node.key")
	if err := os.WriteFile(keyPath, []byte("private"), 0o644); err != nil {
		t.Fatalf("write key fixture: %v", err)
	}
	if err := securePrivateKeyFile(keyPath); err != nil {
		t.Fatalf("securePrivateKeyFile() error = %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key fixture: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("private key permissions = %o, want 600", got)
	}
}

func TestUserLoadRejectsMalformedPrivateKey(t *testing.T) {
	accountPath := filepath.Join(t.TempDir(), "account.json")
	if err := os.WriteFile(accountPath, []byte(`{"Email":"admin@example.test","Key":"not pem"}`), 0o600); err != nil {
		t.Fatalf("write account fixture: %v", err)
	}
	if err := (&User{}).Load(accountPath); err == nil {
		t.Fatal("User.Load() succeeded with an invalid PEM private key")
	}
}

func TestUserSaveCreatesSecureLoadableAccountFile(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate account private key: %v", err)
	}
	accountPath := filepath.Join(t.TempDir(), "account.json")
	user := &User{Email: "admin@example.test", key: key}
	if err := user.Save(accountPath); err != nil {
		t.Fatalf("User.Save() error = %v", err)
	}
	info, err := os.Stat(accountPath)
	if err != nil {
		t.Fatalf("stat account file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("account file permissions = %o, want 600", got)
	}
	var loaded User
	if err := loaded.Load(accountPath); err != nil {
		t.Fatalf("User.Load() error = %v", err)
	}
	if loaded.Email != user.Email {
		t.Fatalf("loaded email = %q, want %q", loaded.Email, user.Email)
	}
}

func TestApplyDNSEnvironmentRestoresProcessEnvironment(t *testing.T) {
	const existingName = "PPANEL_NODE_TEST_DNS_EXISTING"
	const createdName = "PPANEL_NODE_TEST_DNS_CREATED"
	t.Setenv(existingName, "original")
	originalCreatedValue, originalCreatedPresent := os.LookupEnv(createdName)
	defer func() {
		if originalCreatedPresent {
			_ = os.Setenv(createdName, originalCreatedValue)
		} else {
			_ = os.Unsetenv(createdName)
		}
	}()
	_ = os.Unsetenv(createdName)

	restore, err := applyDNSEnvironment("# DNS credentials\r\n\n" + existingName + "=temporary=token==\r\n" + createdName + "=created")
	if err != nil {
		t.Fatalf("applyDNSEnvironment() error = %v", err)
	}
	if got := os.Getenv(existingName); got != "temporary=token==" {
		t.Fatalf("temporary environment value = %q, want temporary=token==", got)
	}
	if got := os.Getenv(createdName); got != "created" {
		t.Fatalf("created environment value = %q, want created", got)
	}
	restore()
	if got := os.Getenv(existingName); got != "original" {
		t.Fatalf("restored environment value = %q, want original", got)
	}
	if _, ok := os.LookupEnv(createdName); ok {
		t.Fatal("created environment variable remains after restore")
	}

	if _, err := applyDNSEnvironment("not-an-assignment"); err == nil {
		t.Fatal("applyDNSEnvironment() accepted an invalid environment line")
	}
}

func TestRenewalReloadSignalAndNativeTLSDetection(t *testing.T) {
	reloadCh := make(chan struct{}, 1)
	controller := &Controller{server: &vCore.XrayCore{ReloadCh: reloadCh}}
	controller.enqueueReload()
	select {
	case <-reloadCh:
	default:
		t.Fatal("enqueueReload() did not signal the reload channel")
	}

	if !usesTLSCertificate(&panel.NodeInfo{Type: "tuic", Protocol: &panel.Protocol{CertMode: "dns"}}) {
		t.Fatal("TUIC with a managed certificate should enable TLS certificate handling")
	}
	if usesTLSCertificate(&panel.NodeInfo{Type: "hysteria", Protocol: &panel.Protocol{CertMode: "none"}}) {
		t.Fatal("Hysteria without a certificate mode should not enable certificate handling")
	}
}

func TestACMEAccountPathSeparatesCustomDirectories(t *testing.T) {
	production := acmeAccountPath("/tmp/certs", "")
	staging := acmeAccountPath("/tmp/certs", "https://acme-staging.example.test/directory")
	if production == staging {
		t.Fatal("custom ACME directory reused the production account path")
	}
	if staging != acmeAccountPath("/tmp/certs", "https://acme-staging.example.test/directory") {
		t.Fatal("ACME account path is not stable for the same directory")
	}
}

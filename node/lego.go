package node

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/file"
)

type Lego struct {
	client *lego.Client
	info   *panel.NodeInfo
}

var dnsProviderEnvMu sync.Mutex

func NewLego(info *panel.NodeInfo) (*Lego, error) {
	certFile, _ := certificatePaths(info)
	caDirURL := strings.TrimSpace(info.ACMECADirURL)
	user, err := newLegoUser(acmeAccountPath(filepath.Dir(certFile), caDirURL),
		strings.TrimSpace(info.ACMEEmail), caDirURL)
	if err != nil {
		return nil, fmt.Errorf("create user error: %s", err)
	}
	c := lego.NewConfig(user)
	if caDirURL != "" {
		c.CADirURL = caDirURL
	}
	c.Certificate.KeyType = certcrypto.EC256
	client, err := lego.NewClient(c)
	if err != nil {
		return nil, err
	}
	l := Lego{
		client: client,
		info:   info,
	}
	err = l.SetProvider()
	if err != nil {
		return nil, fmt.Errorf("set provider error: %s", err)
	}
	return &l, nil
}

func acmeAccountPath(certDir, caDirURL string) string {
	// Retain the old production path so existing installations keep their ACME
	// account. Alternate directories need isolated account state because an ACME
	// account URI (kid) is only valid for the directory that issued it.
	name := "user-ppnode@ppanel.dev.json"
	if caDirURL != "" {
		digest := sha256.Sum256([]byte(caDirURL))
		name = fmt.Sprintf("user-%x.json", digest[:8])
	}
	return filepath.Join(certDir, "user", name)
}

func (l *Lego) SetProvider() error {
	switch strings.TrimSpace(l.info.Protocol.CertMode) {
	case "http":
		err := l.client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80"))
		if err != nil {
			return err
		}
	case "dns":
		// lego's DNS providers read credentials from the process environment
		// while being constructed. Keep that mutation scoped and serialized so
		// separate node renewals cannot leak credentials into one another.
		dnsProviderEnvMu.Lock()
		defer dnsProviderEnvMu.Unlock()
		restore, err := applyDNSEnvironment(l.info.Protocol.CertDNSEnv)
		if err != nil {
			return err
		}
		defer restore()
		p, err := dns.NewDNSChallengeProviderByName(l.info.Protocol.CertDNSProvider)
		if err != nil {
			return fmt.Errorf("create dns challenge provider error: %s", err)
		}
		err = l.client.Challenge.SetDNS01Provider(p)
		if err != nil {
			return fmt.Errorf("set dns provider error: %s", err)
		}
	}
	return nil
}

func applyDNSEnvironment(raw string) (func(), error) {
	env := make(map[string]string)
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSuffix(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("invalid DNS environment line %q", line)
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("DNS environment variable name is empty")
		}
		env[name] = value
	}

	type previousValue struct {
		value   string
		present bool
	}
	previous := make(map[string]previousValue, len(env))
	for name, value := range env {
		oldValue, present := os.LookupEnv(name)
		previous[name] = previousValue{value: oldValue, present: present}
		if err := os.Setenv(name, value); err != nil {
			for restoreName, restoreValue := range previous {
				if restoreValue.present {
					_ = os.Setenv(restoreName, restoreValue.value)
				} else {
					_ = os.Unsetenv(restoreName)
				}
			}
			return nil, fmt.Errorf("set DNS environment variable %q: %w", name, err)
		}
	}

	return func() {
		for name, value := range previous {
			if value.present {
				_ = os.Setenv(name, value.value)
			} else {
				_ = os.Unsetenv(name)
			}
		}
	}, nil
}

func (l *Lego) CreateCert() (err error) {
	request := certificate.ObtainRequest{
		Domains: []string{l.info.Protocol.SNI},
		Bundle:  true,
	}
	certificates, err := l.client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("obtain certificate error: %s", err)
	}
	err = l.writeCert(certificates)
	if err != nil {
		return fmt.Errorf("write certificate error: %s", err)
	}
	return nil
}

func (l *Lego) RenewCert() (bool, error) {
	certFile, keyFile := certificatePaths(l.info)
	leaf, err := loadUsableCertificate(certFile, keyFile, l.info.Protocol.SNI)
	if err != nil {
		// A missing, expired, corrupt, or mismatched pair cannot be renewed.
		// Obtain a new pair so the next reload has a valid certificate.
		if err := l.CreateCert(); err != nil {
			return false, fmt.Errorf("replace unusable certificate: %w", err)
		}
		return true, nil
	}
	if !certificateUsesECDSAP256(leaf) {
		// Passing an RSA private key to lego renewal would retain RSA. Obtain a
		// fresh certificate instead so existing managed installations migrate to
		// the configured ECDSA P-256 key type.
		if err := l.CreateCert(); err != nil {
			return false, fmt.Errorf("replace non-ECDSA certificate: %w", err)
		}
		return true, nil
	}
	if err := securePrivateKeyFile(keyFile); err != nil {
		return false, err
	}
	if time.Until(leaf.NotAfter) > 30*24*time.Hour {
		return false, nil
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return false, fmt.Errorf("read certificate file: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return false, fmt.Errorf("read private key file: %w", err)
	}
	res, err := l.client.Certificate.Renew(certificate.Resource{
		Domain:      l.info.Protocol.SNI,
		Certificate: certPEM,
		PrivateKey:  keyPEM,
	}, true, false, "")
	if err != nil {
		return false, err
	}
	if err := l.writeCert(res); err != nil {
		return false, fmt.Errorf("write certificate error: %w", err)
	}
	return true, nil
}

func (l *Lego) writeCert(certificates *certificate.Resource) error {
	certFile, keyFile := certificatePaths(l.info)
	return writeCertificatePair(certFile, keyFile, certificates.Certificate, certificates.PrivateKey)
}

type User struct {
	Email        string                 `json:"Email"`
	Registration *registration.Resource `json:"Registration"`
	key          crypto.PrivateKey
	KeyEncoded   string `json:"Key"`
}

func (u *User) GetEmail() string {
	return u.Email
}
func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// NewLegoUser preserves the public helper used by callers that use the
// production ACME directory.
func NewLegoUser(path string, email string) (*User, error) {
	return newLegoUser(path, email, "")
}

func newLegoUser(path string, email string, caDirURL string) (*User, error) {
	var user User
	if file.IsExist(path) {
		err := user.Load(path)
		if err != nil {
			return nil, err
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("secure account file permissions: %w", err)
		}
		if (email != "" && user.Email != email) || user.Registration == nil {
			user.Registration = nil
			if email != "" {
				user.Email = email
			}
			err := registerUser(&user, path, caDirURL)
			if err != nil {
				return nil, err
			}
		}
	} else {
		user.Email = email
		err := registerUser(&user, path, caDirURL)
		if err != nil {
			return nil, err
		}
	}
	return &user, nil
}

func registerUser(user *User, path string, caDirURL string) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key error: %s", err)
	}
	user.key = privateKey
	c := lego.NewConfig(user)
	if caDirURL != "" {
		c.CADirURL = caDirURL
	}
	client, err := lego.NewClient(c)
	if err != nil {
		return fmt.Errorf("create lego client error: %s", err)
	}
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	user.Registration = reg
	err = user.Save(path)
	if err != nil {
		return fmt.Errorf("save user error: %s", err)
	}
	return nil
}

func EncodePrivate(privKey *ecdsa.PrivateKey) (string, error) {
	encoded, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})
	return string(pemEncoded), nil
}

func (u *User) Save(path string) error {
	privateKey, ok := u.key.(*ecdsa.PrivateKey)
	if !ok || privateKey == nil {
		return errors.New("ACME account private key is missing or invalid")
	}
	encoded, err := EncodePrivate(privateKey)
	if err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}
	payload, err := json.Marshal(struct {
		Email        string                 `json:"Email"`
		Registration *registration.Resource `json:"Registration"`
		KeyEncoded   string                 `json:"Key"`
	}{
		Email:        u.Email,
		Registration: u.Registration,
		KeyEncoded:   encoded,
	})
	if err != nil {
		return fmt.Errorf("marshal ACME account: %w", err)
	}
	if err := writeFileAtomically(path, payload, 0o600, 0o700); err != nil {
		return fmt.Errorf("write ACME account: %w", err)
	}
	return nil
}

func (u *User) DecodePrivate(pemEncodedPriv string) (*ecdsa.PrivateKey, error) {
	blockPriv, rest := pem.Decode([]byte(pemEncodedPriv))
	if blockPriv == nil {
		return nil, errors.New("decode ACME account private key PEM")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("ACME account private key PEM has trailing data")
	}
	x509EncodedPriv := blockPriv.Bytes
	privateKey, err := x509.ParseECPrivateKey(x509EncodedPriv)
	return privateKey, err
}

func (u *User) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("open file error: %s", err)
	}

	err = json.Unmarshal(data, u)
	if err != nil {
		return fmt.Errorf("unmarshal json error: %s", err)
	}
	if u.KeyEncoded == "" {
		return errors.New("ACME account private key is missing")
	}
	u.key, err = u.DecodePrivate(u.KeyEncoded)
	if err != nil {
		return fmt.Errorf("decode private key error: %s", err)
	}
	return nil
}

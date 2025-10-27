package node

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
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

func NewLego(info *panel.NodeInfo) (*Lego, error) {
	certFile := filepath.Join("/etc/PPanel-node/", info.Type+strconv.Itoa(info.Id)+".cer")
	//keyFile := filepath.Join("/etc/PPanel-node/", info.Type+strconv.Itoa(info.Id)+".key")
	user, err := NewLegoUser(path.Join(path.Dir(certFile),
		"user",
		fmt.Sprintf("user-%s.json", "ppnode@ppanel.dev")),
		"ppnode@ppanel.dev")
	if err != nil {
		return nil, fmt.Errorf("create user error: %s", err)
	}
	c := lego.NewConfig(user)
	//c.CADirURL = "http://192.168.99.100:4000/directory"
	c.Certificate.KeyType = certcrypto.RSA2048
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

func checkPath(p string) error {
	if !file.IsExist(path.Dir(p)) {
		err := os.MkdirAll(path.Dir(p), 0755)
		if err != nil {
			return fmt.Errorf("create dir error: %s", err)
		}
	}
	return nil
}

func (l *Lego) SetProvider() error {
	switch l.info.Protocol.CertMode {
	case "http":
		err := l.client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80"))
		if err != nil {
			return err
		}
	case "dns":
		DnsEnvString := strings.Split(l.info.Protocol.CertDNSEnv, "\n")
		DnsEnv := make(map[string]string)
		for _, line := range DnsEnvString {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				DnsEnv[parts[0]] = parts[1]
			}
		}
		for k, v := range DnsEnv {
			os.Setenv(k, v)
		}
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

func (l *Lego) RenewCert() error {
	certFile := filepath.Join("/etc/PPanel-node/", l.info.Type+strconv.Itoa(l.info.Id)+".cer")
	//keyFile := filepath.Join("/etc/PPanel-node/", info.Type+strconv.Itoa(info.Id)+".key")
	file, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("read cert file error: %s", err)
	}
	if e, err := l.CheckCert(file); !e {
		return nil
	} else if err != nil {
		return fmt.Errorf("check cert error: %s", err)
	}
	res, err := l.client.Certificate.Renew(certificate.Resource{
		Domain:      l.info.Protocol.SNI,
		Certificate: file,
	}, true, false, "")
	if err != nil {
		return err
	}
	err = l.writeCert(res)
	if err != nil {
		return fmt.Errorf("write certificate error: %s", err)
	}
	return nil
}

func (l *Lego) CheckCert(file []byte) (bool, error) {
	cert, err := certcrypto.ParsePEMCertificate(file)
	if err != nil {
		return false, err
	}
	notAfter := int(time.Until(cert.NotAfter).Hours() / 24.0)
	if notAfter > 30 {
		return false, nil
	}
	return true, nil
}

func (l *Lego) writeCert(certificates *certificate.Resource) error {
	certFile := filepath.Join("/etc/PPanel-node/", l.info.Type+strconv.Itoa(l.info.Id)+".cer")
	keyFile := filepath.Join("/etc/PPanel-node/", l.info.Type+strconv.Itoa(l.info.Id)+".key")
	err := checkPath(certFile)
	if err != nil {
		return fmt.Errorf("check path error: %s", err)
	}
	err = os.WriteFile(certFile, certificates.Certificate, 0644)
	if err != nil {
		return err
	}
	err = checkPath(keyFile)
	if err != nil {
		return fmt.Errorf("check path error: %s", err)
	}
	err = os.WriteFile(keyFile, certificates.PrivateKey, 0644)
	if err != nil {
		return err
	}
	return nil
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

func NewLegoUser(path string, email string) (*User, error) {
	var user User
	if file.IsExist(path) {
		err := user.Load(path)
		if err != nil {
			return nil, err
		}
		if user.Email != email {
			user.Registration = nil
			user.Email = email
			err := registerUser(&user, path)
			if err != nil {
				return nil, err
			}
		}
	} else {
		user.Email = email
		err := registerUser(&user, path)
		if err != nil {
			return nil, err
		}
	}
	return &user, nil
}

func registerUser(user *User, path string) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key error: %s", err)
	}
	user.key = privateKey
	c := lego.NewConfig(user)
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
	err := checkPath(path)
	if err != nil {
		return fmt.Errorf("check path error: %s", err)
	}
	u.KeyEncoded, _ = EncodePrivate(u.key.(*ecdsa.PrivateKey))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	err = json.NewEncoder(f).Encode(u)
	if err != nil {
		return fmt.Errorf("marshal json error: %s", err)
	}
	u.KeyEncoded = ""
	return nil
}

func (u *User) DecodePrivate(pemEncodedPriv string) (*ecdsa.PrivateKey, error) {
	blockPriv, _ := pem.Decode([]byte(pemEncodedPriv))
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
	u.key, err = u.DecodePrivate(u.KeyEncoded)
	if err != nil {
		return fmt.Errorf("decode private key error: %s", err)
	}
	return nil
}

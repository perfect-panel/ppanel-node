package conf

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

type Conf struct {
	LogConfig       LogConfig        `mapstructure:"Log"`
	ApiConfig       ServerApiConfig  `mapstructure:"Api"`
	PprofPort       int              `mapstructure:"PprofPort"`
	DefaultOutbound string           `mapstructure:"DefaultOutbound"` // Default outbound tag, empty means "Default" (freedom)
	Outbound        []OutboundConfig `mapstructure:"Outbound"`
}

type LogConfig struct {
	Level  string `mapstructure:"Level"`
	Output string `mapstructure:"Output"`
	Access string `mapstructure:"Access"`
}

type ServerApiConfig struct {
	ApiHost   string `mapstructure:"ApiHost"`
	ServerId  int    `mapstructure:"ServerID"`
	SecretKey string `mapstructure:"SecretKey"`
	Timeout   int    `mapstructure:"Timeout"`
}

type NodeApiConfig struct {
	APIHost   string `mapstructure:"ApiHost"`
	NodeID    int    `mapstructure:"NodeID"`
	SecretKey string `mapstructure:"SecretKey"`
	NodeType  string `mapstructure:"NodeType"`
	Timeout   int    `mapstructure:"Timeout"`
}

type OutboundConfig struct {
	Name             string   `mapstructure:"Name"`
	Protocol         string   `mapstructure:"Protocol"`
	Address          string   `mapstructure:"Address"`
	Port             int      `mapstructure:"Port"`
	User             string   `mapstructure:"User"`
	Password         string   `mapstructure:"Password"`
	Method           string   `mapstructure:"Method"`           // Shadowsocks cipher method
	Flow             string   `mapstructure:"Flow"`             // Trojan/VLESS flow control
	Security         string   `mapstructure:"Security"`         // VMess security / TLS/Reality security
	Encryption       string   `mapstructure:"Encryption"`       // VLESS encryption
	SNI              string   `mapstructure:"SNI"`              // TLS/Reality Server Name Indication
	Insecure         bool     `mapstructure:"Insecure"`         // TLS skip certificate verification
	Fingerprint      string   `mapstructure:"Fingerprint"`      // TLS/Reality browser fingerprint
	RealityPublicKey string   `mapstructure:"RealityPublicKey"` // Reality public key
	RealityShortId   string   `mapstructure:"RealityShortId"`   // Reality short ID
	RealitySpiderX   string   `mapstructure:"RealitySpiderX"`   // Reality spider X path
	WgSecretKey      string   `mapstructure:"WgSecretKey"`      // WireGuard client private key
	WgPublicKey      string   `mapstructure:"WgPublicKey"`      // WireGuard server public key
	WgPreSharedKey   string   `mapstructure:"WgPreSharedKey"`   // WireGuard pre-shared key (optional)
	WgAddress        []string `mapstructure:"WgAddress"`        // WireGuard client IP addresses
	WgMTU            int      `mapstructure:"WgMTU"`            // WireGuard MTU (optional, default 1420)
	WgKeepAlive      int      `mapstructure:"WgKeepAlive"`      // WireGuard keepalive interval (optional)
	WgReserved       []int    `mapstructure:"WgReserved"`       // WireGuard reserved bytes (optional, for WARP)
	Rules            []string `mapstructure:"Rules"`
}

func New() *Conf {
	return &Conf{
		LogConfig: LogConfig{
			Level:  "info",
			Output: "",
			Access: "none",
		},
	}
}

func (p *Conf) LoadFromPath(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open config file error: %s", err)
	}
	defer f.Close()
	v := viper.New()
	v.SetConfigFile(filePath)
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("read config file error: %s", err)
	}
	if err := v.Unmarshal(p); err != nil {
		return fmt.Errorf("unmarshal config error: %s", err)
	}
	return nil
}

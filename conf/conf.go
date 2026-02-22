package conf

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

type Conf struct {
	LogConfig LogConfig        `mapstructure:"Log"`
	ApiConfig ServerApiConfig  `mapstructure:"Api"`
	PprofPort int              `mapstructure:"PprofPort"`
	Outbound  []OutboundConfig `mapstructure:"Outbound"`
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
	Name     string   `mapstructure:"Name"`
	Protocol string   `mapstructure:"Protocol"`
	Address  string   `mapstructure:"Address"`
	Port     int      `mapstructure:"Port"`
	Password string   `mapstructure:"Password"`
	Rules    []string `mapstructure:"Rules"`
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

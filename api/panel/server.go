package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type ServerConfigResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data *Data  `json:"data"`
}

type Data struct {
	TrafficReportThreshold int         `json:"traffic_report_threshold"`
	PushInterval           int         `json:"push_interval"`
	PullInterval           int         `json:"pull_interval"`
	IPStrategy             string      `json:"ip_strategy"`
	DNS                    *[]DNSItem  `json:"dns"`
	Block                  *[]string   `json:"block"`
	Outbound               *[]Outbound `json:"outbound"`
	Protocols              *[]Protocol `json:"protocols"`
	Total                  int         `json:"total"`
}

type DNSItem struct {
	Proto   string   `json:"proto"`
	Address string   `json:"address"`
	Domains []string `json:"domains"`
}

type Outbound struct {
	Name             string   `json:"name"`
	Protocol         string   `json:"protocol"`
	Address          string   `json:"address"`
	Port             int      `json:"port"`
	User             string   `json:"user"`
	Password         string   `json:"password"`
	Method           string   `json:"method"`             // Shadowsocks cipher method
	Flow             string   `json:"flow"`               // Trojan/VLESS flow control
	Security         string   `json:"security"`           // VMess security / TLS/Reality security
	Encryption       string   `json:"encryption"`         // VLESS encryption
	SNI              string   `json:"sni"`                // TLS/Reality Server Name Indication
	Insecure         bool     `json:"insecure"`           // TLS skip certificate verification
	Fingerprint      string   `json:"fingerprint"`        // TLS/Reality browser fingerprint
	RealityPublicKey string   `json:"reality_public_key"` // Reality public key
	RealityShortId   string   `json:"reality_short_id"`   // Reality short ID
	RealitySpiderX   string   `json:"reality_spider_x"`   // Reality spider X path
	WgSecretKey      string   `json:"wg_secret_key"`      // WireGuard client private key
	WgPublicKey      string   `json:"wg_public_key"`      // WireGuard server public key
	WgPreSharedKey   string   `json:"wg_preshared_key"`   // WireGuard pre-shared key (optional)
	WgAddress        []string `json:"wg_address"`         // WireGuard client IP addresses
	WgMTU            int      `json:"wg_mtu"`             // WireGuard MTU (optional, default 1420)
	WgKeepAlive      int      `json:"wg_keepalive"`       // WireGuard keepalive interval (optional)
	WgReserved       []int    `json:"wg_reserved"`        // WireGuard reserved bytes (optional, for WARP)
	Rules            []string `json:"rules"`
}

type Protocol struct {
	Type                    string `json:"type"`
	Port                    int    `json:"port"`
	Enable                  bool   `json:"enable"`
	Security                string `json:"security"`
	SNI                     string `json:"sni"`
	AllowInsecure           bool   `json:"allow_insecure"`
	Fingerprint             string `json:"fingerprint"`
	RealityServerAddr       string `json:"reality_server_addr"`
	RealityServerPort       int    `json:"reality_server_port"`
	RealityPrivateKey       string `json:"reality_private_key"`
	RealityPublicKey        string `json:"reality_public_key"`
	RealityShortID          string `json:"reality_short_id"`
	Transport               string `json:"transport"`
	Host                    string `json:"host"`
	Path                    string `json:"path"`
	ServiceName             string `json:"service_name"`
	Cipher                  string `json:"cipher"`
	ServerKey               string `json:"server_key"`
	Flow                    string `json:"flow"`
	HopPorts                string `json:"hop_ports"`
	HopInterval             int    `json:"hop_interval"`
	ObfsPassword            string `json:"obfs_password"`
	DisableSNI              bool   `json:"disable_sni"`
	ReduceRTT               bool   `json:"reduce_rtt"`
	UDPRelayMode            string `json:"udp_relay_mode"`
	CongestionController    string `json:"congestion_controller"`
	Multiplex               string `json:"multiplex"`
	PaddingScheme           string `json:"padding_scheme"`
	UpMbps                  int    `json:"up_mbps"`
	DownMbps                int    `json:"down_mbps"`
	Obfs                    string `json:"obfs"`
	ObfsHost                string `json:"obfs_host"`
	ObfsPath                string `json:"obfs_path"`
	XHTTPMode               string `json:"xhttp_mode"`
	XHTTPExtra              string `json:"xhttp_extra"`
	Encryption              string `json:"encryption"`
	EncryptionMode          string `json:"encryption_mode"`
	EncryptionRTT           string `json:"encryption_rtt"`
	EncryptionTicket        string `json:"encryption_ticket"`
	EncryptionServerPadding string `json:"encryption_server_padding"`
	EncryptionPrivateKey    string `json:"encryption_private_key"`
	EncryptionClientPadding string `json:"encryption_client_padding"`
	EncryptionPassword      string `json:"encryption_password"`
	CertMode                string `json:"cert_mode"`
	CertDNSProvider         string `json:"cert_dns_provider"`
	CertDNSEnv              string `json:"cert_dns_env"`
}

func GetServerConfig(c *ClientV2) (*ServerConfigResponse, error) {
	client := c.Client
	path := fmt.Sprintf("/v2/server/%d", c.ServerId)
	r, err := client.
		R().
		SetHeader("If-None-Match", c.ServerConfigEtag).
		ForceContentType("application/json").
		Get(path)

	// 优先检查错误,避免处理无效响应
	if err != nil {
		return nil, fmt.Errorf("访问 %s 失败: %v", client.BaseURL+path, err.Error())
	}

	// 检查 HTTP 状态码
	if r.StatusCode() == 304 {
		return nil, nil
	}
	if r.StatusCode() >= 400 {
		body := r.Body()
		return nil, fmt.Errorf("访问 %s 失败: %s", client.BaseURL+path, string(body))
	}

	// 只有在成功响应时才检查 hash
	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	if c.responseBodyHash == newBodyHash {
		return nil, nil
	}
	c.responseBodyHash = newBodyHash
	c.ServerConfigEtag = r.Header().Get("ETag")
	if r != nil {
		defer func() {
			if r.RawBody() != nil {
				r.RawBody().Close()
			}
		}()
	} else {
		return nil, fmt.Errorf("服务端返回为空")
	}
	resp := &ServerConfigResponse{}
	err = json.Unmarshal(r.Body(), resp)
	if err != nil {
		return nil, fmt.Errorf("解码响应体失败: %s", err)
	}
	if resp.Data.Protocols == nil {
		return nil, fmt.Errorf("协议配置为空")
	}
	return resp, nil
}

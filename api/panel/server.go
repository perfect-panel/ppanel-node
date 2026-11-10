package panel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"google.golang.org/protobuf/proto"
)

type ServerConfigResponse struct {
	Code        int    `json:"code"`
	Msg         string `json:"msg"`
	Data        *Data  `json:"data"`
	UseProtobuf bool   `json:"-"`
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
	Proto      string   `json:"proto"`
	Address    string   `json:"address"`
	ServerName string   `json:"server_name"`
	Domains    []string `json:"domains"`
}

type Outbound struct {
	Name                 string   `json:"name"`
	Protocol             string   `json:"protocol"`
	Address              string   `json:"address"`
	Port                 int      `json:"port"`
	User                 string   `json:"user"`
	Password             string   `json:"password"`
	UUID                 string   `json:"uuid"`
	Cipher               string   `json:"cipher"`
	Security             string   `json:"security"`
	SNI                  string   `json:"sni"`
	AllowInsecure        bool     `json:"allow_insecure"`
	Fingerprint          string   `json:"fingerprint"`
	Transport            string   `json:"transport"`
	Host                 string   `json:"host"`
	Path                 string   `json:"path"`
	ServiceName          string   `json:"service_name"`
	Flow                 string   `json:"flow"`
	UoT                  bool     `json:"uot"`
	UoTVersion           int      `json:"uot_version"`
	CongestionController string   `json:"congestion_controller"`
	UDPStream            bool     `json:"udp_stream"`
	ReduceRTT            bool     `json:"reduce_rtt"`
	Heartbeat            int      `json:"heartbeat"`
	RealityPublicKey     string   `json:"reality_public_key"`
	RealityShortID       string   `json:"reality_short_id"`
	SpiderX              string   `json:"spider_x"`
	Settings             string   `json:"settings"`
	StreamSettings       string   `json:"stream_settings"`
	Rules                []string `json:"rules"`
}

type Protocol struct {
	Type                    string   `json:"type"`
	Version                 int      `json:"version"`
	Mode                    string   `json:"mode"`
	Network                 string   `json:"network"`
	ALPN                    []string `json:"alpn"`
	Port                    int      `json:"port"`
	Enable                  bool     `json:"enable"`
	Security                string   `json:"security"`
	SNI                     string   `json:"sni"`
	AllowInsecure           bool     `json:"allow_insecure"`
	Fingerprint             string   `json:"fingerprint"`
	RealityServerAddr       string   `json:"reality_server_addr"`
	RealityServerPort       int      `json:"reality_server_port"`
	RealityPrivateKey       string   `json:"reality_private_key"`
	RealityPublicKey        string   `json:"reality_public_key"`
	RealityShortID          string   `json:"reality_short_id"`
	Transport               string   `json:"transport"`
	Host                    string   `json:"host"`
	Path                    string   `json:"path"`
	ServiceName             string   `json:"service_name"`
	Cipher                  string   `json:"cipher"`
	ServerKey               string   `json:"server_key"`
	Flow                    string   `json:"flow"`
	UoT                     bool     `json:"uot"`
	UoTVersion              int      `json:"uot_version"`
	AcceptProxyProtocol     bool     `json:"accept_proxy_protocol"`
	HopPorts                string   `json:"hop_ports"`
	HopInterval             int      `json:"hop_interval"`
	ObfsPassword            string   `json:"obfs_password"`
	DisableSNI              bool     `json:"disable_sni"`
	ReduceRTT               bool     `json:"reduce_rtt"`
	UDPRelayMode            string   `json:"udp_relay_mode"`
	CongestionController    string   `json:"congestion_controller"`
	Multiplex               string   `json:"multiplex"`
	PaddingScheme           string   `json:"padding_scheme"`
	UpMbps                  int      `json:"up_mbps"`
	DownMbps                int      `json:"down_mbps"`
	Obfs                    string   `json:"obfs"`
	ObfsHost                string   `json:"obfs_host"`
	ObfsPath                string   `json:"obfs_path"`
	XHTTPMode               string   `json:"xhttp_mode"`
	XHTTPExtra              string   `json:"xhttp_extra"`
	Encryption              string   `json:"encryption"`
	EncryptionMode          string   `json:"encryption_mode"`
	EncryptionRTT           string   `json:"encryption_rtt"`
	EncryptionTicket        string   `json:"encryption_ticket"`
	EncryptionServerPadding string   `json:"encryption_server_padding"`
	EncryptionPrivateKey    string   `json:"encryption_private_key"`
	EncryptionClientPadding string   `json:"encryption_client_padding"`
	EncryptionPassword      string   `json:"encryption_password"`
	EchEnable               bool     `json:"ech_enable"`
	EchServerName           string   `json:"ech_server_name"`
	Ratio                   float64  `json:"ratio"`
	CertMode                string   `json:"cert_mode"`
	CertDNSProvider         string   `json:"cert_dns_provider"`
	CertDNSEnv              string   `json:"cert_dns_env"`
}

func GetServerConfig(ctx context.Context, c *ServerClient) (*ServerConfigResponse, error) {
	client := c.Client
	path := fmt.Sprintf("/v2/server/%d", c.ServerId)
	request := client.R().
		SetContext(ctx).
		SetHeader("If-None-Match", c.ServerConfigEtag)
	setProtobufResponseAccept(request)
	r, err := request.Get(path)

	// 优先检查错误,避免处理无效响应
	if err != nil {
		return nil, fmt.Errorf("访问 %s 失败: %v", client.BaseURL+path, err.Error())
	}

	if err := checkHTTPResponse(r, client.BaseURL+path); err != nil {
		return nil, err
	}

	defer func() {
		if r.RawBody() != nil {
			r.RawBody().Close()
		}
	}()
	if r.StatusCode() == 304 {
		return nil, nil
	}

	body := r.Body()
	resp := &ServerConfigResponse{}
	if isProtobufResponse(r) {
		message := &serverv1.QueryServerProtocolConfigResponse{}
		if err := proto.Unmarshal(body, message); err != nil {
			return nil, fmt.Errorf("解码 Protobuf 响应体失败: %w", err)
		}
		resp = serverConfigResponseFromProtobuf(message)
	} else if err := json.Unmarshal(body, resp); err != nil {
		return nil, fmt.Errorf("解码响应体失败: %s", err)
	}
	c.UseProtobuf = isProtobufResponse(r)
	resp.UseProtobuf = c.UseProtobuf
	if err := checkPanelEnvelope(resp.Code, resp.Msg, client.BaseURL+path); err != nil {
		return nil, err
	}
	if resp.Data == nil {
		return nil, fmt.Errorf("服务端配置为空")
	}
	if resp.Data.Protocols == nil {
		return nil, fmt.Errorf("协议配置为空")
	}
	if etag := r.Header().Get("ETag"); etag != "" {
		c.ServerConfigEtag = etag
	}

	hash := sha256.Sum256(body)
	newBodyHash := hex.EncodeToString(hash[:])
	if c.responseBodyHash == newBodyHash {
		return nil, nil
	}
	c.responseBodyHash = newBodyHash
	return resp, nil
}

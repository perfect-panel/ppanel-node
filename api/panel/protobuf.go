package panel

import (
	"fmt"
	"mime"
	"strings"

	"github.com/go-resty/resty/v2"
	serverv1 "github.com/perfect-panel/ppanel-node/api/server/v1"
	"google.golang.org/protobuf/proto"
)

const protobufContentType = "application/protobuf"

func setProtobufRequestBody(request *resty.Request, message proto.Message) error {
	body, err := proto.Marshal(message)
	if err != nil {
		return fmt.Errorf("编码 Protobuf 请求失败: %w", err)
	}
	request.SetBody(body).
		SetHeader("Content-Type", protobufContentType).
		SetHeader("Accept", protobufContentType)
	return nil
}

func setProtobufResponseAccept(request *resty.Request) {
	request.SetHeader("Accept", protobufContentType)
}

func isProtobufResponse(response *resty.Response) bool {
	if response == nil {
		return false
	}
	contentType, _, err := mime.ParseMediaType(response.Header().Get("Content-Type"))
	return err == nil && strings.EqualFold(contentType, protobufContentType)
}

func unmarshalProtobufResult(body []byte) (*serverv1.Result, error) {
	result := &serverv1.Result{}
	if err := proto.Unmarshal(body, result); err != nil {
		return nil, fmt.Errorf("解码 Protobuf 响应体失败: %w", err)
	}
	return result, nil
}

func serverConfigResponseFromProtobuf(message *serverv1.QueryServerProtocolConfigResponse) *ServerConfigResponse {
	response := &ServerConfigResponse{
		Code: int(message.Code),
		Msg:  message.Message,
	}
	if message.Data == nil {
		return response
	}

	dns := make([]DNSItem, 0, len(message.Data.Dns))
	for _, item := range message.Data.Dns {
		if item == nil {
			continue
		}
		dns = append(dns, DNSItem{
			Proto:      item.Proto,
			Address:    item.Address,
			ServerName: item.ServerName,
			Domains:    append([]string(nil), item.Domains...),
		})
	}

	outbound := make([]Outbound, 0, len(message.Data.Outbound))
	for _, item := range message.Data.Outbound {
		if item == nil {
			continue
		}
		outbound = append(outbound, Outbound{
			Name: item.Name, Protocol: item.Protocol, Address: item.Address, Port: int(item.Port),
			User: item.User, Password: item.Password, UUID: item.Uuid, Cipher: item.Cipher,
			Security: item.Security, SNI: item.Sni, AllowInsecure: item.AllowInsecure,
			Fingerprint: item.Fingerprint, Transport: item.Transport, Host: item.Host, Path: item.Path,
			ServiceName: item.ServiceName, Flow: item.Flow, UoT: item.Uot,
			UoTVersion: int(item.UotVersion), CongestionController: item.CongestionController,
			UDPStream: item.UdpStream, ReduceRTT: item.ReduceRtt, Heartbeat: int(item.Heartbeat),
			RealityPublicKey: item.RealityPublicKey, RealityShortID: item.RealityShortId,
			SpiderX: item.SpiderX, Settings: item.Settings, StreamSettings: item.StreamSettings,
			Rules: append([]string(nil), item.Rules...),
		})
	}

	protocols := make([]Protocol, 0, len(message.Data.Protocols))
	for _, item := range message.Data.Protocols {
		if item == nil {
			continue
		}
		protocols = append(protocols, Protocol{
			Type: item.Type, Port: int(item.Port), Enable: item.Enable, Security: item.Security,
			Version: int(item.Version), Mode: item.Mode, Network: item.Network, ALPN: append([]string(nil), item.Alpn...),
			SNI: item.Sni, AllowInsecure: item.AllowInsecure, Fingerprint: item.Fingerprint,
			RealityServerAddr: item.RealityServerAddr, RealityServerPort: int(item.RealityServerPort),
			RealityPrivateKey: item.RealityPrivateKey, RealityPublicKey: item.RealityPublicKey,
			RealityShortID: item.RealityShortId, Transport: item.Transport, Host: item.Host,
			Path: item.Path, ServiceName: item.ServiceName, Cipher: item.Cipher, ServerKey: item.ServerKey,
			Flow: item.Flow, UoT: item.Uot, UoTVersion: int(item.UotVersion),
			AcceptProxyProtocol: item.AcceptProxyProtocol, HopPorts: item.HopPorts,
			HopInterval: int(item.HopInterval), ObfsPassword: item.ObfsPassword, DisableSNI: item.DisableSni,
			ReduceRTT: item.ReduceRtt, UDPRelayMode: item.UdpRelayMode,
			CongestionController: item.CongestionController, Multiplex: item.Multiplex,
			PaddingScheme: item.PaddingScheme, UpMbps: int(item.UpMbps), DownMbps: int(item.DownMbps),
			Obfs: item.Obfs, ObfsHost: item.ObfsHost, ObfsPath: item.ObfsPath, XHTTPMode: item.XhttpMode,
			XHTTPExtra: item.XhttpExtra, Encryption: item.Encryption, EncryptionMode: item.EncryptionMode,
			EncryptionRTT: item.EncryptionRtt, EncryptionTicket: item.EncryptionTicket,
			EncryptionServerPadding: item.EncryptionServerPadding, EncryptionPrivateKey: item.EncryptionPrivateKey,
			EncryptionClientPadding: item.EncryptionClientPadding, EncryptionPassword: item.EncryptionPassword,
			EchEnable: item.EchEnable, EchServerName: item.EchServerName, Ratio: item.Ratio,
			CertMode: item.CertMode, CertDNSProvider: item.CertDnsProvider, CertDNSEnv: item.CertDnsEnv,
		})
	}

	response.Data = &Data{
		TrafficReportThreshold: int(message.Data.TrafficReportThreshold),
		PushInterval:           int(message.Data.PushInterval),
		PullInterval:           int(message.Data.PullInterval),
		IPStrategy:             message.Data.IpStrategy,
		DNS:                    &dns,
		Block:                  ptrToSlice(append([]string(nil), message.Data.Block...)),
		Outbound:               &outbound,
		Protocols:              &protocols,
		Total:                  int(message.Data.Total),
	}
	return response
}

func ptrToSlice(values []string) *[]string {
	return &values
}
